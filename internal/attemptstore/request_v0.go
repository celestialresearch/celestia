// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

package attemptstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"celestia.research/governed-operation/internal/urlreference"
)

const (
	requestV0Operation      = "url-reference"
	requestV0MediaType      = "text/plain; charset=utf-8"
	requestV0StartTimeoutMS = 12000
	requestV0LegacyStartMS  = 2000
	requestV0TimeoutMS      = 2000
	requestV0InputMax       = 4096
	requestV0OutputMax      = 8192
	requestV0StderrMax      = 8192
	requestV0MemoryMax      = 67108864
	requestV0Processes      = 1
	requestV0FrameMax       = 65536
)

var decimalV0 = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type requestV0 struct {
	ProtocolVersion  int      `json:"protocol_version"`
	OperationID      string   `json:"operation_id"`
	OperationVersion int      `json:"operation_version"`
	AttemptID        string   `json:"attempt_id"`
	RequestNonce     string   `json:"request_nonce"`
	InputMediaType   string   `json:"input_media_type"`
	InputLength      int      `json:"input_length"`
	InputSHA256      string   `json:"input_sha256"`
	Mode             string   `json:"mode"`
	Deadline         string   `json:"deadline"`
	TimeoutMS        int      `json:"timeout_ms"`
	Limits           limitsV0 `json:"limits"`
	Input            string   `json:"input"`
}

type limitsV0 struct {
	InputBytes  int `json:"input_bytes"`
	OutputBytes int `json:"output_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	MemoryBytes int `json:"memory_bytes"`
	Processes   int `json:"processes"`
}

func decodeRequestV0(data []byte, admittedAt time.Time) (requestV0, error) {
	if len(data) == 0 || len(data) > requestV0FrameMax || !utf8.Valid(data) {
		return requestV0{}, ErrCorrupt
	}
	if !validRequestV0Frame(data) {
		return requestV0{}, ErrCorrupt
	}
	var request requestV0
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return requestV0{}, ErrCorrupt
	}
	if !validRequestV0(request, admittedAt) {
		return requestV0{}, ErrCorrupt
	}
	return request, nil
}

func validRequestV0Frame(data []byte) bool {
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil ||
		!bytes.Equal(compact.Bytes(), data) ||
		hasUnpairedSurrogateV0(data) {
		return false
	}
	fields, ok := objectFieldsV0(data)
	if !ok || !requestFieldsV0(fields) {
		return false
	}
	limits, ok := objectFieldsV0(fields["limits"])
	return ok && limitFieldsV0(limits)
}

func requestFieldsV0(fields map[string]json.RawMessage) bool {
	integers := []string{"protocol_version", "operation_version", "input_length", "timeout_ms"}
	strings := []string{
		"operation_id", "attempt_id", "request_nonce", "input_media_type",
		"input_sha256", "mode", "deadline", "input",
	}
	if len(fields) != len(integers)+len(strings)+1 {
		return false
	}
	for _, name := range integers {
		if !decimalV0.Match(fields[name]) {
			return false
		}
	}
	for _, name := range strings {
		if !rawStringV0(fields[name]) {
			return false
		}
	}
	_, ok := fields["limits"]
	return ok
}

func limitFieldsV0(fields map[string]json.RawMessage) bool {
	required := []string{"input_bytes", "output_bytes", "stderr_bytes", "memory_bytes", "processes"}
	if len(fields) != len(required) {
		return false
	}
	for _, name := range required {
		if !decimalV0.Match(fields[name]) {
			return false
		}
	}
	return true
}

func objectFieldsV0(data []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		name, stringKey := token.(string)
		if err != nil || !stringKey {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, false
	}
	_, err = decoder.Token()
	return fields, err == io.EOF
}

func rawStringV0(data json.RawMessage) bool {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(data, &value) == nil
}

func hasUnpairedSurrogateV0(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[index] != '\\' {
			continue
		}
		next, invalid := inspectEscapedRuneV0(data, index)
		if invalid {
			return true
		}
		index = next
	}
	return false
}

func inspectEscapedRuneV0(data []byte, index int) (int, bool) {
	if index+5 >= len(data) || data[index+1] != 'u' {
		return min(index+1, len(data)-1), false
	}
	value, ok := decodeHexV0(data[index+2 : index+6])
	if !ok || value&0xf800 != 0xd800 {
		return index + 5, false
	}
	if value&0xfc00 == 0xdc00 {
		return index + 5, true
	}
	if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
		return index + 5, true
	}
	low, ok := decodeHexV0(data[index+8 : index+12])
	return index + 11, !ok || low&0xfc00 != 0xdc00
}

func decodeHexV0(data []byte) (uint16, bool) {
	value, err := strconv.ParseUint(string(data), 16, 16)
	return uint16(value), err == nil && len(data) == 4
}

func validRequestV0(request requestV0, admittedAt time.Time) bool {
	if request.ProtocolVersion != 0 ||
		request.OperationID != requestV0Operation ||
		request.OperationVersion != 0 ||
		request.InputMediaType != requestV0MediaType ||
		request.TimeoutMS != requestV0TimeoutMS ||
		!validCorrelationV0(request) ||
		(request.Mode != "fang" && request.Mode != "defang") {
		return false
	}
	if !validRequestV0Input(request) || !validRequestV0Deadline(request.Deadline, admittedAt) {
		return false
	}
	return request.Limits == (limitsV0{
		InputBytes:  requestV0InputMax,
		OutputBytes: requestV0OutputMax,
		StderrBytes: requestV0StderrMax,
		MemoryBytes: requestV0MemoryMax,
		Processes:   requestV0Processes,
	})
}

func validCorrelationV0(request requestV0) bool {
	return validIdentityV0(request.AttemptID) &&
		validIdentityV0(request.RequestNonce) &&
		request.AttemptID != request.RequestNonce
}

func validIdentityV0(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validRequestV0Input(request requestV0) bool {
	if !utf8.ValidString(request.Input) ||
		len(request.Input) < 1 ||
		len(request.Input) > requestV0InputMax ||
		request.InputLength != len(request.Input) {
		return false
	}
	hash := sha256.Sum256([]byte(request.Input))
	return request.InputSHA256 == hex.EncodeToString(hash[:]) &&
		urlreference.ValidateInput(request.Input) == nil
}

func validRequestV0Deadline(value string, admittedAt time.Time) bool {
	if !strings.HasSuffix(value, "Z") {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	current := admittedAt.UTC().Add(requestV0StartTimeoutMS * time.Millisecond)
	legacy := admittedAt.UTC().Add(requestV0LegacyStartMS * time.Millisecond)
	return err == nil &&
		parsed.Format(time.RFC3339Nano) == value &&
		(parsed.Equal(current) || parsed.Equal(legacy))
}
