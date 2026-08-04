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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeResponse(t *testing.T) {
	t.Parallel()

	request := testRequest()
	correlation := testCorrelation(t, request)
	response := testResponse(request)
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}

	actual, err := decodeResponse(data, correlation, 0)
	if err != nil {
		t.Fatalf("decodeResponse() error = %v", err)
	}
	if actual.Output == nil || *actual.Output != *response.Output {
		t.Fatalf("decodeResponse() output = %v", actual.Output)
	}
}
func TestDecodeResponseForRequestCorrelation(t *testing.T) {
	t.Parallel()

	request := testRequest()
	response := testResponse(request)
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponseForRequestCorrelation(data, request, 0); err != nil {
		t.Fatalf("DecodeResponseForRequestCorrelation() error = %v", err)
	}

	tests := map[string]func(*Request){
		"attempt": func(request *Request) { request.AttemptID = "invalid" },
		"nonce":   func(request *Request) { request.RequestNonce = "invalid" },
		"repeated": func(request *Request) {
			request.RequestNonce = request.AttemptID
		},
		"media": func(request *Request) {
			request.InputMediaType = "application/octet-stream"
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			invalid := request
			change(&invalid)
			if _, err := DecodeResponseForRequestCorrelation(
				data,
				invalid,
				0,
			); !errors.Is(err, ErrProtocol) {
				t.Fatalf("invalid request correlation error = %v, want ErrProtocol", err)
			}
		})
	}
}
func TestDecodeResponseRejects(t *testing.T) {
	t.Parallel()

	request := testRequest()
	correlation := testCorrelation(t, request)
	valid := validResponseJSON(t, request)
	tests := []struct {
		name     string
		data     string
		exitCode int
	}{
		{"empty", "", 0},
		{"oversized", strings.Repeat("x", MaxResponseBytes+1), 0},
		{"invalid UTF-8", string([]byte{0xff}), 0},
		{"whitespace", " " + valid, 0},
		{"trailing newline", valid + "\n", 0},
		{"unpaired high surrogate", strings.Replace(valid, `"completed"`, `"\ud800"`, 1), 0},
		{"unpaired low surrogate", strings.Replace(valid, `"completed"`, `"\udc00"`, 1), 0},
		{"malformed", "{", 0},
		{"duplicate", strings.Replace(valid, `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1), 0},
		{"unknown", strings.Replace(valid, "{", `{"unknown":0,`, 1), 0},
		{"missing protocol", removeField(valid, "protocol_version"), 0},
		{"missing duration", removeField(valid, "duration_ns"), 0},
		{"missing diagnostics", removeField(valid, "diagnostics"), 0},
		{"null diagnostics", strings.Replace(valid, `"diagnostics":[]`, `"diagnostics":null`, 1), 0},
		{"null protocol", strings.Replace(valid, `"protocol_version":1`, `"protocol_version":null`, 1), 0},
		{"negative zero protocol", strings.Replace(valid, `"protocol_version":1`, `"protocol_version":-0`, 1), 0},
		{"null duration", strings.Replace(valid, `"duration_ns":1000`, `"duration_ns":null`, 1), 0},
		{"null worker ID", strings.Replace(valid, `"worker_id":"celestia-url-reference"`, `"worker_id":null`, 1), 0},
		{"wrong protocol", strings.Replace(valid, `"protocol_version":1`, `"protocol_version":2`, 1), 0},
		{"wrong operation", strings.Replace(valid, `"operation_id":"url-reference"`, `"operation_id":"other"`, 1), 0},
		{"wrong operation version", strings.Replace(valid, `"operation_version":1`, `"operation_version":2`, 1), 0},
		{"wrong attempt", strings.Replace(valid, request.AttemptID, "other", 1), 0},
		{"wrong nonce", strings.Replace(valid, request.RequestNonce, "other", 1), 0},
		{"wrong worker", strings.Replace(valid, `"worker_id":"celestia-url-reference"`, `"worker_id":"other"`, 1), 0},
		{"wrong worker version", strings.Replace(valid, `"worker_version":"1"`, `"worker_version":"2"`, 1), 0},
		{"negative duration", strings.Replace(valid, `"duration_ns":1000`, `"duration_ns":-1`, 1), 0},
		{"long duration", strings.Replace(valid, `"duration_ns":1000`, `"duration_ns":2000000001`, 1), 0},
		{"unsupported status", strings.Replace(valid, `"status":"completed"`, `"status":"other"`, 1), 0},
		{"wrong completed exit", valid, 3},
		{"missing output", removeField(valid, "output"), 0},
		{"null output", strings.Replace(valid, `"output":"hxxps://example[.]test/"`, `"output":null`, 1), 0},
		{"wrong media type", strings.Replace(valid, MediaType, "application/octet-stream", 1), 0},
		{"zero output length", replaceNumber(valid, "output_length", 0), 0},
		{"null output length", strings.Replace(valid, `"output_length":23`, `"output_length":null`, 1), 0},
		{"large output length", replaceNumber(valid, "output_length", MaxOutputBytes+1), 0},
		{"length mismatch", replaceNumber(valid, "output_length", 1), 0},
		{"hash mismatch", strings.Replace(valid, `"output_sha256":"`, `"output_sha256":"0`, 1), 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeResponse([]byte(test.data), correlation, test.exitCode)
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeResponse() error = %v, want ErrProtocol", err)
			}
		})
	}
}
func TestDecodeResponseRejectsCorrelation(t *testing.T) {
	t.Parallel()

	request := testRequest()
	data := []byte(validResponseJSON(t, request))
	correlation := testCorrelation(t, request)
	tests := []struct {
		name        string
		correlation responseCorrelation
	}{
		{name: "all fields", correlation: responseCorrelation{}},
		{
			name: "attempt identifier",
			correlation: responseCorrelation{
				attemptID: base64.RawURLEncoding.EncodeToString(
					bytes.Repeat([]byte{0xC3}, 32),
				),
				nonce:     correlation.nonce,
				mediaType: correlation.mediaType,
			},
		},
		{
			name: "request nonce",
			correlation: responseCorrelation{
				attemptID: correlation.attemptID,
				nonce: base64.RawURLEncoding.EncodeToString(
					bytes.Repeat([]byte{0xD4}, 32),
				),
				mediaType: correlation.mediaType,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeResponse(
				data, test.correlation, 0,
			); !errors.Is(err, ErrProtocol) {
				t.Fatalf(
					"decodeResponse() error = %v, want ErrProtocol", err,
				)
			}
		})
	}
}
func TestDecodeResponseStatuses(t *testing.T) {
	t.Parallel()

	request := testRequest()
	correlation := testCorrelation(t, request)
	tests := []struct {
		name        string
		status      Status
		exitCode    int
		diagnostics []Diagnostic
		wantError   bool
	}{
		{"rejected", Rejected, 2, []Diagnostic{{Code: "invalid_input", Message: "input rejected"}}, false},
		{"failed", Failed, 3, []Diagnostic{{Code: "worker_failed", Message: "worker failed"}}, false},
		{"rejected wrong exit", Rejected, 3, []Diagnostic{{Code: "invalid_input", Message: "input rejected"}}, true},
		{"failed wrong exit", Failed, 2, []Diagnostic{{Code: "worker_failed", Message: "worker failed"}}, true},
		{"missing diagnostic", Rejected, 2, []Diagnostic{}, true},
		{"bad code", Failed, 3, []Diagnostic{{Code: "BAD", Message: "worker failed"}}, true},
		{"long message", Failed, 3, []Diagnostic{{Code: "worker_failed", Message: strings.Repeat("x", MaxMessageBytes+1)}}, true},
		{"too many diagnostics", Failed, 3, repeatDiagnostic(MaxDiagnostics + 1), true},
		{"null message", Failed, 3, []Diagnostic{{Code: "worker_failed", Message: "worker failed"}}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := Response{
				ProtocolVersion:  ProtocolVersion,
				OperationID:      OperationID,
				OperationVersion: OperationVersion,
				AttemptID:        request.AttemptID,
				RequestNonce:     request.RequestNonce,
				WorkerID:         WorkerID,
				WorkerVersion:    WorkerVersion,
				Status:           test.status,
				Diagnostics:      test.diagnostics,
				DurationNS:       1,
			}
			data, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "null message" {
				data = []byte(strings.Replace(string(data), `"message":"worker failed"`, `"message":null`, 1))
			}
			_, err = decodeResponse(data, correlation, test.exitCode)
			if test.wantError && !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeResponse() error = %v, want ErrProtocol", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("decodeResponse() error = %v", err)
			}
		})
	}
}
func TestDecodeResponseRejectsDiagnosticFields(t *testing.T) {
	t.Parallel()

	request := testRequest()
	correlation := testCorrelation(t, request)
	response := Response{
		ProtocolVersion:  ProtocolVersion,
		OperationID:      OperationID,
		OperationVersion: OperationVersion,
		AttemptID:        request.AttemptID,
		RequestNonce:     request.RequestNonce,
		WorkerID:         WorkerID,
		WorkerVersion:    WorkerVersion,
		Status:           Failed,
		Diagnostics: []Diagnostic{{
			Code:    "worker_failed",
			Message: "worker failed",
		}},
		DurationNS: 1,
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	tests := []struct {
		name string
		data string
	}{
		{
			name: "missing code",
			data: strings.Replace(
				valid,
				`{"code":"worker_failed","message":"worker failed"}`,
				`{"message":"worker failed"}`,
				1,
			),
		},
		{
			name: "extra field",
			data: strings.Replace(
				valid,
				`{"code":"worker_failed","message":"worker failed"}`,
				`{"code":"worker_failed","message":"worker failed","unknown":true}`,
				1,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeResponse(
				[]byte(test.data),
				correlation,
				3,
			); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeResponse() error = %v, want ErrProtocol", err)
			}
		})
	}
}
func TestValidateStatusRejectsUnknown(t *testing.T) {
	t.Parallel()

	request := testRequest()
	response := Response{Status: "unknown"}
	if err := validateStatus(response, testCorrelation(t, request), 1); !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}
func testResponse(request Request) Response {
	output := "hxxps://example[.]test/"
	hash := sha256.Sum256([]byte(output))
	return Response{
		ProtocolVersion:  ProtocolVersion,
		OperationID:      OperationID,
		OperationVersion: OperationVersion,
		AttemptID:        request.AttemptID,
		RequestNonce:     request.RequestNonce,
		WorkerID:         WorkerID,
		WorkerVersion:    WorkerVersion,
		Status:           Completed,
		OutputMediaType:  new(MediaType),
		OutputLength:     new(len(output)),
		OutputSHA256:     new(hex.EncodeToString(hash[:])),
		Output:           new(output),
		Diagnostics:      []Diagnostic{},
		DurationNS:       1000,
	}
}
func testCorrelation(tb testing.TB, request Request) responseCorrelation {
	tb.Helper()
	if err := validateRequest(request, testAdmittedAt()); err != nil {
		tb.Fatal(err)
	}
	return correlationFor(request)
}
func validResponseJSON(tb testing.TB, request Request) string {
	tb.Helper()
	output := "hxxps://example[.]test/"
	hash := sha256.Sum256([]byte(output))
	response := Response{
		ProtocolVersion:  ProtocolVersion,
		OperationID:      OperationID,
		OperationVersion: OperationVersion,
		AttemptID:        request.AttemptID,
		RequestNonce:     request.RequestNonce,
		WorkerID:         WorkerID,
		WorkerVersion:    WorkerVersion,
		Status:           Completed,
		OutputMediaType:  new(MediaType),
		OutputLength:     new(len(output)),
		OutputSHA256:     new(hex.EncodeToString(hash[:])),
		Output:           new(output),
		Diagnostics:      []Diagnostic{},
		DurationNS:       1000,
	}
	data, err := json.Marshal(response)
	if err != nil {
		tb.Fatal(err)
	}
	return string(data)
}
func removeField(data, field string) string {
	var value map[string]any
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		panic(err)
	}
	delete(value, field)
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
func replaceNumber(data, field string, value int) string {
	var object map[string]any
	if err := json.Unmarshal([]byte(data), &object); err != nil {
		panic(err)
	}
	object[field] = value
	encoded, err := json.Marshal(object)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
func repeatDiagnostic(count int) []Diagnostic {
	result := make([]Diagnostic, count)
	for index := range result {
		result[index] = Diagnostic{Code: "worker_failed", Message: "worker failed"}
	}
	return result
}
