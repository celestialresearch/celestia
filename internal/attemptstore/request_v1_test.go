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
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"celestia.research/celestia/internal/workerprotocolv1"
)

func TestDecodeRequestV1(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV1(accepted.Frame, admittedAt)
	if err != nil {
		t.Fatalf("decode v1 request: %v", err)
	}
	if request.AttemptID != accepted.Request.AttemptID ||
		request.Input != accepted.Request.Input {
		t.Fatal("decoded v1 request lost admitted bindings")
	}
}

func TestDecodeRequestV1RejectsNonCanonicalFrame(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	tests := map[string][]byte{
		"trailing whitespace": append(bytes.Clone(accepted.Frame), '\n'),
		"unknown field":       append(bytes.TrimSuffix(accepted.Frame, []byte("}")), []byte(`,"extra":0}`)...),
		"duplicate field":     append(bytes.TrimSuffix(accepted.Frame, []byte("}")), []byte(`,"protocol_version":1}`)...),
		"duplicate limit": bytes.Replace(
			accepted.Frame,
			[]byte(`"processes":1}`),
			[]byte(`"processes":1,"processes":1}`),
			1,
		),
		"missing field": bytes.Replace(
			accepted.Frame,
			[]byte(`"operation_id":"url-reference",`),
			nil,
			1,
		),
		"negative integer": bytes.Replace(
			accepted.Frame,
			[]byte(`"protocol_version":1`),
			[]byte(`"protocol_version":-1`),
			1,
		),
		"integer overflow": bytes.Replace(
			accepted.Frame,
			[]byte(`"protocol_version":1`),
			[]byte(`"protocol_version":999999999999999999999999999999`),
			1,
		),
		"negative limit": bytes.Replace(
			accepted.Frame,
			[]byte(`"input_bytes":4096`),
			[]byte(`"input_bytes":-1`),
			1,
		),
		"null string": bytes.Replace(
			accepted.Frame,
			[]byte(`"attempt_id":"`+accepted.Request.AttemptID+`"`),
			[]byte(`"attempt_id":null`),
			1,
		),
		"unpaired surrogate": bytes.Replace(
			accepted.Frame,
			[]byte(`"url-reference"`),
			[]byte(`"\ud800"`),
			1,
		),
		"wrong surrogate literal": bytes.Replace(
			accepted.Frame,
			[]byte(`"url-reference"`),
			[]byte(`"url-\ud83d\ude00"`),
			1,
		),
		"unpaired low surrogate": bytes.Replace(
			accepted.Frame,
			[]byte(`"url-reference"`),
			[]byte(`"\udc00"`),
			1,
		),
		"missing low surrogate": bytes.Replace(
			accepted.Frame,
			[]byte(`"url-reference"`),
			[]byte(`"\ud800x"`),
			1,
		),
		"root array":   []byte(`[]`),
		"invalid JSON": []byte(`{`),
		"invalid UTF-8": {
			0xff,
		},
		"oversized": bytes.Repeat([]byte{'x'}, requestV1FrameMax+1),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("non-canonical v1 frame accepted: %v", err)
			}
		})
	}
}

func TestDecodeRequestV1RejectsRepeatedCorrelation(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	frame := bytes.Replace(
		accepted.Frame,
		[]byte(accepted.Request.RequestNonce),
		[]byte(accepted.Request.AttemptID),
		1,
	)
	if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("repeated correlation accepted: %v", err)
	}
}

func TestDecodeRequestV1DoesNotReplayGrammar(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV1(accepted.Frame, admittedAt)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	request.Input = "not-a-url-reference"
	request.InputLength = len(request.Input)
	hash := sha256.Sum256([]byte(request.Input))
	request.InputSHA256 = hex.EncodeToString(hash[:])
	frame, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode invalid reference: %v", err)
	}
	if _, err := decodeRequestV1(frame, admittedAt); err != nil {
		t.Fatalf("retained frame depends on current grammar: %v", err)
	}
}

func TestRetainedObservationDoesNotReplayTransform(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	observation := testObservationFor(t, accepted)
	var response workerprotocol.Response
	if err := json.Unmarshal(observation.Stdout, &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	output := "retained-v1-output"
	outputLength := len(output)
	outputHash := sha256.Sum256([]byte(output))
	outputHashText := hex.EncodeToString(outputHash[:])
	response.Output = &output
	response.OutputLength = &outputLength
	response.OutputSHA256 = &outputHashText
	var err error
	observation.Stdout, err = json.Marshal(response)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	observation.ExpectedOutput = output

	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	if err := validateRetainedObservationEvidence(admitted, observation); err != nil {
		t.Fatalf("retained evidence replayed transformation: %v", err)
	}
	if err := validateObservationEvidence(admitted, observation); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("publication skipped transformation: %v", err)
	}
}

func TestDecodeRequestV1AcceptsEquivalentJSON(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	escaped := bytes.Replace(accepted.Frame, []byte("url-reference"), []byte(`url\u002dreference`), 1)
	escapedSlash := bytes.Replace(accepted.Frame, []byte(`"input":"https://`), []byte(`"input":"https:\/\/`), 1)
	first := []byte(`"protocol_version":1,`)
	reordered := bytes.Replace(accepted.Frame, first, nil, 1)
	reordered = append(bytes.TrimSuffix(reordered, []byte("}")), []byte(`,"protocol_version":1}`)...)
	for name, frame := range map[string][]byte{
		"escaped":       escaped,
		"escaped slash": escapedSlash,
		"reordered":     reordered,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequestV1(frame, admittedAt); err != nil {
				t.Fatalf("equivalent v1 JSON rejected: %v", err)
			}
		})
	}
}

func TestDecodeRequestV1RejectsSurrogateAfterQuote(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV1(accepted.Frame, admittedAt)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	request.Input = "https://example.test/a\"\ufffd"
	request.InputLength = len(request.Input)
	hash := sha256.Sum256([]byte(request.Input))
	request.InputSHA256 = hex.EncodeToString(hash[:])
	frame, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	frame = bytes.Replace(frame, []byte("\ufffd"), []byte(`\ud800`), 1)
	if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unpaired surrogate after escaped quote accepted: %v", err)
	}
}

func TestValidateAdmittedRejectsUnknownVersion(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	record := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	record.Version = 2
	if err := validateAdmitted(record); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown admitted version accepted: %v", err)
	}
}

func TestObjectFieldsV1RejectsMalformed(t *testing.T) {
	tests := map[string][]byte{
		"non-object":    []byte(`[]`),
		"duplicate":     []byte(`{"x":0,"x":1}`),
		"invalid key":   []byte(`{1:0}`),
		"missing value": []byte(`{"x":}`),
		"missing close": []byte(`{"x":0`),
		"trailing data": []byte(`{}x`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := objectFieldsV1(data); ok {
				t.Fatal("malformed v1 object decoded")
			}
		})
	}
}

func TestRequestV1FieldValidators(t *testing.T) {
	validRequestFields := map[string]json.RawMessage{
		"protocol_version":  []byte("1"),
		"operation_id":      []byte(`"url-reference"`),
		"operation_version": []byte("1"),
		"attempt_id":        []byte(`"attempt"`),
		"request_nonce":     []byte(`"nonce"`),
		"input_media_type":  []byte(`"text/plain; charset=utf-8"`),
		"input_length":      []byte("1"),
		"input_sha256":      []byte(`"hash"`),
		"mode":              []byte(`"fang"`),
		"deadline":          []byte(`"deadline"`),
		"timeout_ms":        []byte("2000"),
		"limits":            []byte(`{}`),
		"input":             []byte(`"x"`),
	}
	for name, mutate := range map[string]func(map[string]json.RawMessage){
		"wrong count": func(fields map[string]json.RawMessage) {
			delete(fields, "input")
		},
		"non-decimal integer": func(fields map[string]json.RawMessage) {
			fields["input_length"] = []byte("-1")
		},
		"non-string": func(fields map[string]json.RawMessage) {
			fields["input"] = []byte("1")
		},
		"missing limits": func(fields map[string]json.RawMessage) {
			delete(fields, "limits")
			fields["replacement"] = []byte(`{}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fields := make(map[string]json.RawMessage, len(validRequestFields))
			for key, value := range validRequestFields {
				fields[key] = bytes.Clone(value)
			}
			mutate(fields)
			if requestFieldsV1(fields) {
				t.Fatal("invalid request fields accepted")
			}
		})
	}

	validLimits := map[string]json.RawMessage{
		"input_bytes":  []byte("4096"),
		"output_bytes": []byte("8192"),
		"stderr_bytes": []byte("8192"),
		"memory_bytes": []byte("67108864"),
		"processes":    []byte("1"),
	}
	if !limitFieldsV1(validLimits) {
		t.Fatal("valid limits rejected")
	}
	delete(validLimits, "processes")
	if limitFieldsV1(validLimits) {
		t.Fatal("incomplete limits accepted")
	}
	validLimits["processes"] = []byte("-1")
	if limitFieldsV1(validLimits) {
		t.Fatal("non-decimal limit accepted")
	}
}

func TestRequestV1EscapeHelpers(t *testing.T) {
	for name, test := range map[string]struct {
		data    string
		next    int
		invalid bool
	}{
		"ordinary escape": {data: `\n`, next: 1},
		"non-surrogate":   {data: `\u1234`, next: 5},
		"invalid hex":     {data: `\u12x4`, next: 5},
		"low surrogate":   {data: `\udc00`, next: 5, invalid: true},
		"invalid low":     {data: `\ud800\u12x4`, next: 11, invalid: true},
	} {
		t.Run(name, func(t *testing.T) {
			next, invalid := inspectEscapedRuneV1([]byte(test.data), 0)
			if next != test.next || invalid != test.invalid {
				t.Fatalf(
					"inspectEscapedRuneV1()=(%d,%t), want (%d,%t)",
					next,
					invalid,
					test.next,
					test.invalid,
				)
			}
		})
	}
	for name, data := range map[string]string{
		"wrong length": "123",
		"invalid":      "12x4",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := decodeHexV1([]byte(data)); ok {
				t.Fatal("invalid hexadecimal escape accepted")
			}
		})
	}
}

func TestRequestV1ValueBindings(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV1(accepted.Frame, admittedAt)
	if err != nil {
		t.Fatal(err)
	}
	request.InputLength++
	if validRequestV1Input(request) {
		t.Fatal("input length mismatch accepted")
	}
	request.InputLength--
	request.Deadline = "not-a-deadline"
	if validRequestV1(request, admittedAt) {
		t.Fatal("invalid retained deadline accepted")
	}
	if validRequestV1Deadline(
		admittedAt.Add(requestV1StartTimeoutMS*time.Millisecond).Format(time.RFC3339),
		admittedAt,
	) {
		t.Fatal("non-canonical deadline accepted")
	}
	if validRequestV1Deadline("not-a-deadline", admittedAt) {
		t.Fatal("invalid deadline accepted")
	}
	if validRequestV1Deadline("not-a-timeZ", admittedAt) {
		t.Fatal("invalid Z-suffixed deadline accepted")
	}
}

func TestDecodeRequestV1RejectsTypedIntegerOverflow(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	frame := bytes.Replace(
		accepted.Frame,
		[]byte(`"protocol_version":1`),
		[]byte(`"protocol_version":999999999999999999999999999999`),
		1,
	)
	if !validRequestV1Frame(frame) {
		t.Fatal("overflow fixture did not reach the typed decoder")
	}
	if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("integer overflow accepted: %v", err)
	}
}

func TestRawStringV1RejectsEmpty(t *testing.T) {
	if rawStringV1(nil) || rawStringV1([]byte("null")) {
		t.Fatal("empty raw string accepted")
	}
}

func FuzzDecodeRequestV1(f *testing.F) {
	accepted, admittedAt := testAccepted(f)
	f.Add(accepted.Frame)
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, frame []byte) {
		request, err := decodeRequestV1(frame, admittedAt)
		if err != nil {
			return
		}
		if !validRequestV1(request, admittedAt) {
			t.Fatal("decoder accepted an invalid v1 request")
		}
		canonical, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal accepted v1 request: %v", err)
		}
		decoded, err := decodeRequestV1(canonical, admittedAt)
		if err != nil || decoded != request {
			t.Fatalf("canonical v1 request did not round trip: decoded=%+v error=%v", decoded, err)
		}
	})
}
