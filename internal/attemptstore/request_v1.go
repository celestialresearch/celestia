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

//go:build windows

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

	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

const (
	requestV1Operation      = "url-reference"
	requestV1MediaType      = "text/plain; charset=utf-8"
	requestV1StartTimeoutMS = 12000
	requestV1TimeoutMS      = 2000
	requestV1InputMax       = 4096
	requestV1OutputMax      = 8192
	requestV1StderrMax      = 8192
	requestV1MemoryMax      = 67108864
	requestV1Processes      = 1
	requestV1FrameMax       = 65536
)

var decimalV1 = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type requestV1 struct {
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
	Limits           limitsV1 `json:"limits"`
	Input            string   `json:"input"`
}

type limitsV1 struct {
	InputBytes  int `json:"input_bytes"`
	OutputBytes int `json:"output_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	MemoryBytes int `json:"memory_bytes"`
	Processes   int `json:"processes"`
}

func (request requestV1) workerRequest() workerprotocol.Request {
	return workerprotocol.Request{
		ProtocolVersion:  request.ProtocolVersion,
		OperationID:      request.OperationID,
		OperationVersion: request.OperationVersion,
		AttemptID:        request.AttemptID,
		RequestNonce:     request.RequestNonce,
		InputMediaType:   request.InputMediaType,
		InputLength:      request.InputLength,
		InputSHA256:      request.InputSHA256,
		Mode:             request.Mode,
		Deadline:         request.Deadline,
		TimeoutMS:        request.TimeoutMS,
		Limits: workerprotocol.Limits{
			InputBytes:  request.Limits.InputBytes,
			OutputBytes: request.Limits.OutputBytes,
			StderrBytes: request.Limits.StderrBytes,
			MemoryBytes: request.Limits.MemoryBytes,
			Processes:   request.Limits.Processes,
		},
		Input: request.Input,
	}
}

func decodeRequestV1(data []byte, admittedAt time.Time) (requestV1, error) {
	if len(data) == 0 || len(data) > requestV1FrameMax || !utf8.Valid(data) {
		return requestV1{}, ErrCorrupt
	}
	if !validRequestV1Frame(data) {
		return requestV1{}, ErrCorrupt
	}
	var request requestV1
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return requestV1{}, ErrCorrupt
	}
	if !validRequestV1(request, admittedAt) {
		return requestV1{}, ErrCorrupt
	}
	return request, nil
}

func validRequestV1Frame(data []byte) bool {
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil ||
		!bytes.Equal(compact.Bytes(), data) ||
		hasUnpairedSurrogateV1(data) {
		return false
	}
	fields, ok := objectFieldsV1(data)
	if !ok || !requestFieldsV1(fields) {
		return false
	}
	limits, ok := objectFieldsV1(fields["limits"])
	return ok && limitFieldsV1(limits)
}

func requestFieldsV1(fields map[string]json.RawMessage) bool {
	integers := []string{"protocol_version", "operation_version", "input_length", "timeout_ms"}
	strings := []string{
		"operation_id", "attempt_id", "request_nonce", "input_media_type",
		"input_sha256", "mode", "deadline", "input",
	}
	if len(fields) != len(integers)+len(strings)+1 {
		return false
	}
	for _, name := range integers {
		if !decimalV1.Match(fields[name]) {
			return false
		}
	}
	for _, name := range strings {
		if !rawStringV1(fields[name]) {
			return false
		}
	}
	_, ok := fields["limits"]
	return ok
}

func limitFieldsV1(fields map[string]json.RawMessage) bool {
	required := []string{"input_bytes", "output_bytes", "stderr_bytes", "memory_bytes", "processes"}
	if len(fields) != len(required) {
		return false
	}
	for _, name := range required {
		if !decimalV1.Match(fields[name]) {
			return false
		}
	}
	return true
}

func objectFieldsV1(data []byte) (map[string]json.RawMessage, bool) {
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

func rawStringV1(data json.RawMessage) bool {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(data, &value) == nil
}

func hasUnpairedSurrogateV1(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[index] != '\\' {
			continue
		}
		next, invalid := inspectEscapedRuneV1(data, index)
		if invalid {
			return true
		}
		index = next
	}
	return false
}

func inspectEscapedRuneV1(data []byte, index int) (int, bool) {
	if index+5 >= len(data) || data[index+1] != 'u' {
		return min(index+1, len(data)-1), false
	}
	value, ok := decodeHexV1(data[index+2 : index+6])
	if !ok || value&0xf800 != 0xd800 {
		return index + 5, false
	}
	if value&0xfc00 == 0xdc00 {
		return index + 5, true
	}
	if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
		return index + 5, true
	}
	low, ok := decodeHexV1(data[index+8 : index+12])
	return index + 11, !ok || low&0xfc00 != 0xdc00
}

func decodeHexV1(data []byte) (uint16, bool) {
	value, err := strconv.ParseUint(string(data), 16, 16)
	return uint16(value), err == nil && len(data) == 4
}

func validRequestV1(request requestV1, admittedAt time.Time) bool {
	if request.ProtocolVersion != 1 ||
		request.OperationID != requestV1Operation ||
		request.OperationVersion != 1 ||
		request.InputMediaType != requestV1MediaType ||
		request.TimeoutMS != requestV1TimeoutMS ||
		!validCorrelationV1(request) ||
		(request.Mode != "fang" && request.Mode != "defang") {
		return false
	}
	if !validRequestV1Input(request) || !validRequestV1Deadline(request.Deadline, admittedAt) {
		return false
	}
	return request.Limits == (limitsV1{
		InputBytes:  requestV1InputMax,
		OutputBytes: requestV1OutputMax,
		StderrBytes: requestV1StderrMax,
		MemoryBytes: requestV1MemoryMax,
		Processes:   requestV1Processes,
	})
}

func validCorrelationV1(request requestV1) bool {
	return validIdentityV1(request.AttemptID) &&
		validIdentityV1(request.RequestNonce) &&
		request.AttemptID != request.RequestNonce
}

func validIdentityV1(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validRequestV1Input(request requestV1) bool {
	if !utf8.ValidString(request.Input) ||
		len(request.Input) < 1 ||
		len(request.Input) > requestV1InputMax ||
		request.InputLength != len(request.Input) {
		return false
	}
	hash := sha256.Sum256([]byte(request.Input))
	return request.InputSHA256 == hex.EncodeToString(hash[:])
}

func validRequestV1Deadline(value string, admittedAt time.Time) bool {
	if !strings.HasSuffix(value, "Z") {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	current := admittedAt.UTC().Add(requestV1StartTimeoutMS * time.Millisecond)
	return err == nil &&
		parsed.Format(time.RFC3339Nano) == value &&
		parsed.Equal(current)
}
