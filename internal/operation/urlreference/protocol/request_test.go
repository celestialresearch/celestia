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
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateRequestRejects(t *testing.T) {
	t.Parallel()

	valid := testRequest()
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{"constants", func(request *Request) { request.ProtocolVersion = 2 }},
		{"attempt", func(request *Request) { request.AttemptID = "attempt" }},
		{"attempt alphabet", func(request *Request) { request.AttemptID = "!" }},
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
			if _, err := validateRequest(request, testAdmittedAt()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("validateRequest() error = %v, want ErrProtocol", err)
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
		strings.Replace(
			frame,
			`"input_length":21`,
			`"input_length":999999999999999999999999999999999999`,
			1,
		),
		strings.Replace(frame, `"mode":"defang"`, `"mode":"invalid"`, 1),
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
func testAdmittedAt() time.Time {
	return time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
}
func setRequestInput(request *Request, input string) {
	hash := sha256.Sum256([]byte(input))
	request.Input = input
	request.InputLength = len(input)
	request.InputSHA256 = hex.EncodeToString(hash[:])
}
