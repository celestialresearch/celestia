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

package workerprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func validateRequestFields(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocolError("request field set")
	}
	required := []string{
		"protocol_version", "operation_id", "operation_version", "attempt_id",
		"request_nonce", "input_media_type", "input_length", "input_sha256",
		"mode", "deadline", "timeout_ms", "limits", "input",
	}
	if err := requireFields(fields, required); err != nil {
		return err
	}
	for _, name := range []string{"protocol_version", "operation_version", "input_length", "timeout_ms"} {
		if !decimalInteger.Match(fields[name]) {
			return protocolError("request integer field")
		}
	}
	for _, name := range []string{
		"operation_id", "attempt_id", "request_nonce", "input_media_type",
		"input_sha256", "mode", "deadline", "input",
	} {
		if !rawString(fields[name]) {
			return protocolError("request string field")
		}
	}
	return validateLimitFields(fields["limits"])
}

func validateLimitFields(data json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocolError("limits field")
	}
	required := []string{"input_bytes", "output_bytes", "stderr_bytes", "memory_bytes", "processes"}
	if err := requireFields(fields, required); err != nil {
		return err
	}
	for _, name := range required {
		if !decimalInteger.Match(fields[name]) {
			return protocolError("limit integer field")
		}
	}
	return nil
}

func requireFields(fields map[string]json.RawMessage, required []string) error {
	if len(fields) != len(required) {
		return protocolError("field set")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return protocolError("missing field")
		}
	}
	return nil
}

func validateFields(data []byte, status Status) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocolError("field set")
	}
	required := []string{
		"protocol_version", "operation_id", "operation_version", "attempt_id",
		"request_nonce", "worker_id", "worker_version", "status", "diagnostics",
		"duration_ns",
	}
	if status == Completed {
		required = append(required, "output_media_type", "output_length", "output_sha256", "output")
	}
	if err := requireFields(fields, required); err != nil {
		return err
	}
	if diagnostics := fields["diagnostics"]; diagnostics[0] != '[' {
		return protocolError("diagnostics type")
	}
	return validateRawFields(fields, status)
}

func validateRawFields(fields map[string]json.RawMessage, status Status) error {
	for _, name := range []string{"protocol_version", "operation_version", "duration_ns"} {
		if !decimalInteger.Match(fields[name]) {
			return protocolError("integer field")
		}
	}
	for _, name := range []string{
		"operation_id", "attempt_id", "request_nonce", "worker_id", "worker_version", "status",
	} {
		if !rawString(fields[name]) {
			return protocolError("string field")
		}
	}
	if status == Completed {
		if !decimalInteger.Match(fields["output_length"]) {
			return protocolError("output length type")
		}
		for _, name := range []string{"output_media_type", "output_sha256", "output"} {
			if !rawString(fields[name]) {
				return protocolError("output string type")
			}
		}
	}
	return validateRawDiagnostics(fields["diagnostics"])
}

func validateRawDiagnostics(data json.RawMessage) error {
	var diagnostics []map[string]json.RawMessage
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		return protocolError("diagnostics decode")
	}
	for _, diagnostic := range diagnostics {
		if !rawString(diagnostic["code"]) || !rawString(diagnostic["message"]) {
			return protocolError("diagnostic fields")
		}
	}
	return nil
}

func rawString(data json.RawMessage) bool {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(data, &value) == nil
}

func validateJSONFrame(data []byte) error {
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil || !bytes.Equal(compact.Bytes(), data) {
		return protocolError("frame")
	}
	if hasUnpairedSurrogate(data) {
		return protocolError("unpaired surrogate")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanValue(decoder, 0); err != nil {
		return err
	}
	return nil
}

func hasUnpairedSurrogate(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[index] != '\\' {
			continue
		}
		next, invalid := inspectEscapedRune(data, index)
		if invalid {
			return true
		}
		index = next
	}
	return false
}

func inspectEscapedRune(data []byte, index int) (int, bool) {
	if index+5 >= len(data) || data[index+1] != 'u' {
		return min(index+1, len(data)-1), false
	}
	value, ok := decodeHex4(data[index+2 : index+6])
	if !ok || value&0xf800 != 0xd800 {
		return index + 5, false
	}
	if value&0xfc00 == 0xdc00 {
		return index + 5, true
	}
	if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
		return index + 5, true
	}
	low, ok := decodeHex4(data[index+8 : index+12])
	if !ok || low&0xfc00 != 0xdc00 {
		return index + 5, true
	}
	return index + 11, false
}

func decodeHex4(data []byte) (uint16, bool) {
	if len(data) != 4 {
		return 0, false
	}
	var value uint16
	for _, digit := range data {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func scanValue(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONDepth {
		return protocolError("JSON nesting depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return protocolError("token")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return scanObject(decoder, depth)
	case '[':
		return scanArray(decoder, depth)
	default:
		return protocolError("unexpected delimiter")
	}
}

func scanObject(decoder *json.Decoder, depth int) error {
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return protocolError("object key")
		}
		key, ok := token.(string)
		if !ok {
			return protocolError("object key")
		}
		if _, duplicate := keys[key]; duplicate {
			return protocolError("duplicate field")
		}
		keys[key] = struct{}{}
		if err := scanValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return expectDelimiter(decoder, '}')
}

func scanArray(decoder *json.Decoder, depth int) error {
	for decoder.More() {
		if err := scanValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return expectDelimiter(decoder, ']')
}

func expectDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return protocolError("closing delimiter")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return protocolError("closing delimiter")
	}
	return nil
}

func protocolError(message string) error {
	return fmt.Errorf("%w: %s", ErrProtocol, message)
}
