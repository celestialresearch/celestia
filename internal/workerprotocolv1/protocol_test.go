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
	"time"
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

	actual, err := DecodeResponse(data, correlation, 0)
	if err != nil {
		t.Fatalf("DecodeResponse() error = %v", err)
	}
	if actual.Output == nil || *actual.Output != *response.Output {
		t.Fatalf("DecodeResponse() output = %v", actual.Output)
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

func TestJSONFrameDepthLimit(t *testing.T) {
	t.Parallel()

	within := strings.Repeat("[", MaxJSONDepth) + "0" + strings.Repeat("]", MaxJSONDepth)
	if err := validateJSONFrame([]byte(within)); err != nil {
		t.Fatalf("bounded JSON nesting rejected: %v", err)
	}
	excessive := "[" + within + "]"
	if err := validateJSONFrame([]byte(excessive)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("excessive JSON nesting accepted: %v", err)
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
			_, err := DecodeResponse([]byte(test.data), correlation, test.exitCode)
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeResponse() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDecodeResponseRejectsCorrelation(t *testing.T) {
	t.Parallel()

	request := testRequest()
	data := []byte(validResponseJSON(t, request))
	if _, err := DecodeResponse(data, Correlation{}, 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("DecodeResponse() error = %v, want ErrProtocol", err)
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
			_, err = DecodeResponse(data, correlation, test.exitCode)
			if test.wantError && !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeResponse() error = %v, want ErrProtocol", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("DecodeResponse() error = %v", err)
			}
		})
	}
}

func TestValidateRequestRejects(t *testing.T) {
	t.Parallel()

	valid := testRequest()
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{"constants", func(request *Request) { request.ProtocolVersion = 2 }},
		{"attempt", func(request *Request) { request.AttemptID = "attempt" }},
		{"repeated correlation", func(request *Request) {
			request.RequestNonce = request.AttemptID
		}},
		{"mode", func(request *Request) { request.Mode = "other" }},
		{"input", func(request *Request) { request.Input = "" }},
		{"length", func(request *Request) { request.InputLength++ }},
		{"hash", func(request *Request) { request.InputSHA256 = strings.Repeat("0", 64) }},
		{"deadline", func(request *Request) { request.Deadline = "2026-07-25T00:00:00+10:00" }},
		{"deadline syntax", func(request *Request) { request.Deadline = "not-a-timeZ" }},
		{"deadline mismatch", func(request *Request) { request.Deadline = "2026-07-25T00:00:03Z" }},
		{"limits", func(request *Request) { request.Limits.Processes = 2 }},
		{"URL grammar", func(request *Request) { setRequestInput(request, "hello") }},
		{"URL state", func(request *Request) { setRequestInput(request, "http://example[.]test/") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := valid
			test.mutate(&request)
			if _, err := ValidateRequest(request, testAdmittedAt()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("ValidateRequest() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestRequestFrame(t *testing.T) {
	t.Parallel()

	request := testRequest()
	data, correlation, err := EncodeRequest(request, testAdmittedAt())
	if err != nil {
		t.Fatalf("EncodeRequest() error = %v", err)
	}
	actual, decodedCorrelation, err := DecodeRequest(data, testAdmittedAt())
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	if actual != request || decodedCorrelation != correlation {
		t.Fatal("request round trip changed data")
	}
}

func TestEncodeRequestRejects(t *testing.T) {
	t.Parallel()

	request := testRequest()
	request.AttemptID = "invalid"
	if _, _, err := EncodeRequest(request, testAdmittedAt()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("EncodeRequest() error = %v, want ErrProtocol", err)
	}
}

func TestDecodeRequestRejects(t *testing.T) {
	t.Parallel()

	valid, _, err := EncodeRequest(testRequest(), testAdmittedAt())
	if err != nil {
		t.Fatal(err)
	}
	frame := string(valid)
	tests := []string{
		"",
		string([]byte{0xff}),
		" " + frame,
		strings.Replace(frame, `"url-reference"`, `"\ud800"`, 1),
		strings.Replace(frame, `"url-reference"`, `"\udc00"`, 1),
		strings.Replace(frame, `"protocol_version":1`, `"protocol_version":-0`, 1),
		strings.Replace(frame, `"protocol_version":1`, `"protocol_version":null`, 1),
		strings.Replace(frame, `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1),
		removeField(frame, "protocol_version"),
		strings.Replace(frame, `"limits":{`, `"limits":{"unknown":0,`, 1),
		strings.Replace(frame, `"input_bytes":4096`, `"input_bytes":0e0`, 1),
		strings.Replace(frame, `"input_bytes":4096`, `"input_bytes":null`, 1),
		strings.Replace(frame, `"operation_id":"url-reference"`, `"operation_id":null`, 1),
	}
	for _, data := range tests {
		if _, _, err := DecodeRequest([]byte(data), testAdmittedAt()); !errors.Is(err, ErrProtocol) {
			t.Fatalf("DecodeRequest(%q) error = %v, want ErrProtocol", data, err)
		}
	}
}

func TestHasUnpairedSurrogate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		data   string
		paired bool
	}{
		{"high", `{"value":"\ud800"}`, false},
		{"low", `{"value":"\udc00"}`, false},
		{"wrong pair", `{"value":"\ud800\u0041"}`, false},
		{"pair", `{"value":"\ud83d\ude00"}`, true},
		{"escaped text", `{"value":"\\ud800"}`, true},
		{"escaped quote then high", `{"value":"\"\ud800"}`, false},
		{"escaped quote then low", `{"value":"\"\udc00"}`, false},
		{"escaped quote then pair", `{"value":"\"\ud83d\ude00"}`, true},
		{"escaped slash then high", `{"value":"\\\ud800"}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := !hasUnpairedSurrogate([]byte(test.data)); got != test.paired {
				t.Fatalf("paired = %t, want %t", got, test.paired)
			}
		})
	}
}

func TestValidateRawDiagnosticsRejects(t *testing.T) {
	t.Parallel()

	if err := validateRawDiagnostics([]byte(`[`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

func TestRawRequestFieldsRejectMalformed(t *testing.T) {
	t.Parallel()

	if err := validateRequestFields([]byte(`{`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("request fields error = %v, want ErrProtocol", err)
	}
	if err := validateLimitFields([]byte(`{`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("limits fields error = %v, want ErrProtocol", err)
	}
}

func TestValidateFieldsRejects(t *testing.T) {
	t.Parallel()

	if err := validateFields([]byte(`{`), Completed); !errors.Is(err, ErrProtocol) {
		t.Fatalf("malformed error = %v, want ErrProtocol", err)
	}
	data := []byte(`{"protocol_version":1,"operation_id":"url-reference","operation_version":1,"attempt_id":"attempt","request_nonce":"nonce","worker_id":"celestia-url-reference","worker_version":"1","status":"failed","unknown":[],"duration_ns":0}`)
	if err := validateFields(data, Failed); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing field error = %v, want ErrProtocol", err)
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

func TestProtocolScannerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func() error
	}{
		{"missing value", func() error { return scanValue(json.NewDecoder(bytes.NewBuffer(nil)), 0) }},
		{"unexpected delimiter", unexpectedDelimiter},
		{"missing object key", func() error { return scanObject(json.NewDecoder(bytes.NewBuffer(nil)), 0) }},
		{"non-string object key", func() error { return scanObject(json.NewDecoder(bytes.NewBufferString(`1`)), 0) }},
		{"invalid object key", invalidObjectKey},
		{"invalid object value", invalidObjectValue},
		{"invalid array value", func() error { return scanArray(json.NewDecoder(bytes.NewBufferString(`{`)), 0) }},
		{"missing delimiter", func() error { return expectDelimiter(json.NewDecoder(bytes.NewBuffer(nil)), '}') }},
		{"wrong delimiter", wrongDelimiter},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.run(); !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want ErrProtocol", err)
			}
		})
	}
}

func unexpectedDelimiter() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`[]`))
	_, _ = decoder.Token()
	return scanValue(decoder, 0)
}

func invalidObjectKey() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`[tru`))
	_, _ = decoder.Token()
	return scanObject(decoder, 0)
}

func invalidObjectValue() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`{"a"`))
	_, _ = decoder.Token()
	return scanObject(decoder, 0)
}

func wrongDelimiter() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`[]`))
	_, _ = decoder.Token()
	return expectDelimiter(decoder, '}')
}

func FuzzDecodeResponse(f *testing.F) {
	request := testRequest()
	correlation := testCorrelation(f, request)
	f.Add([]byte(validResponseJSON(f, request)), 0)
	f.Add([]byte(`{}`), 0)
	f.Add([]byte(`{"a":[{"b":1}]}`), 0)

	f.Fuzz(func(t *testing.T, data []byte, exitCode int) {
		response, err := DecodeResponse(data, correlation, exitCode)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("marshal accepted response: %v", err)
		}
		if _, err := DecodeResponse(encoded, correlation, exitCode); err != nil {
			t.Fatalf("round-trip response rejected: %v", err)
		}
	})
}

func FuzzDecodeRequest(f *testing.F) {
	valid, _, err := EncodeRequest(testRequest(), testAdmittedAt())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"protocol_version":-0}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		request, _, err := DecodeRequest(data, testAdmittedAt())
		if err != nil {
			return
		}
		encoded, _, err := EncodeRequest(request, testAdmittedAt())
		if err != nil {
			t.Fatalf("encode accepted request: %v", err)
		}
		if _, _, err := DecodeRequest(encoded, testAdmittedAt()); err != nil {
			t.Fatalf("round-trip request rejected: %v", err)
		}
	})
}

func testRequest() Request {
	input := "https://example.test/"
	hash := sha256.Sum256([]byte(input))
	return Request{
		ProtocolVersion:  ProtocolVersion,
		OperationID:      OperationID,
		OperationVersion: OperationVersion,
		AttemptID:        base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xA1}, 32)),
		RequestNonce:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xB2}, 32)),
		InputMediaType:   MediaType,
		InputLength:      len(input),
		InputSHA256:      hex.EncodeToString(hash[:]),
		Mode:             "defang",
		Deadline:         "2026-07-25T00:00:12Z",
		TimeoutMS:        TimeoutMS,
		Limits: Limits{
			InputBytes:  InputBytes,
			OutputBytes: MaxOutputBytes,
			StderrBytes: StderrBytes,
			MemoryBytes: MemoryBytes,
			Processes:   Processes,
		},
		Input: input,
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

func testCorrelation(tb testing.TB, request Request) Correlation {
	tb.Helper()
	correlation, err := ValidateRequest(request, testAdmittedAt())
	if err != nil {
		tb.Fatal(err)
	}
	return correlation
}

func testAdmittedAt() time.Time {
	return time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
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

func setRequestInput(request *Request, input string) {
	hash := sha256.Sum256([]byte(input))
	request.Input = input
	request.InputLength = len(input)
	request.InputSHA256 = hex.EncodeToString(hash[:])
}
