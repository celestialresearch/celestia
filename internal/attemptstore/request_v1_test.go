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
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"celestia.research/governed-operation/internal/workerprotocolv1"
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
