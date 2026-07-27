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
)

func TestDecodeRequestV0(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV0(accepted.Frame, admittedAt)
	if err != nil {
		t.Fatalf("decode v0 request: %v", err)
	}
	if request.AttemptID != accepted.Request.AttemptID ||
		request.Input != accepted.Request.Input {
		t.Fatal("decoded v0 request lost admitted bindings")
	}
}

func TestDecodeRequestV0RejectsNonCanonicalFrame(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	tests := map[string][]byte{
		"trailing whitespace": append(bytes.Clone(accepted.Frame), '\n'),
		"unknown field":       append(bytes.TrimSuffix(accepted.Frame, []byte("}")), []byte(`,"extra":0}`)...),
		"duplicate field":     append(bytes.TrimSuffix(accepted.Frame, []byte("}")), []byte(`,"protocol_version":0}`)...),
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
			[]byte(`"protocol_version":0`),
			[]byte(`"protocol_version":-1`),
			1,
		),
		"integer overflow": bytes.Replace(
			accepted.Frame,
			[]byte(`"protocol_version":0`),
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
		"oversized": bytes.Repeat([]byte{'x'}, requestV0FrameMax+1),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequestV0(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("non-canonical v0 frame accepted: %v", err)
			}
		})
	}
}

func TestDecodeRequestV0RejectsRepeatedCorrelation(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	frame := bytes.Replace(
		accepted.Frame,
		[]byte(accepted.Request.RequestNonce),
		[]byte(accepted.Request.AttemptID),
		1,
	)
	if _, err := decodeRequestV0(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("repeated correlation accepted: %v", err)
	}
}

func TestDecodeRequestV0RejectsInvalidReference(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV0(accepted.Frame, admittedAt)
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
	if _, err := decodeRequestV0(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid v0 reference accepted: %v", err)
	}
}

func TestDecodeRequestV0AcceptsEquivalentJSON(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	escaped := bytes.Replace(accepted.Frame, []byte("url-reference"), []byte(`url\u002dreference`), 1)
	escapedSlash := bytes.Replace(accepted.Frame, []byte(`"input":"https://`), []byte(`"input":"https:\/\/`), 1)
	first := []byte(`"protocol_version":0,`)
	reordered := bytes.Replace(accepted.Frame, first, nil, 1)
	reordered = append(bytes.TrimSuffix(reordered, []byte("}")), []byte(`,"protocol_version":0}`)...)
	for name, frame := range map[string][]byte{
		"escaped":       escaped,
		"escaped slash": escapedSlash,
		"reordered":     reordered,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequestV0(frame, admittedAt); err != nil {
				t.Fatalf("equivalent v0 JSON rejected: %v", err)
			}
		})
	}
}

func TestDecodeRequestV0RejectsSurrogateAfterQuote(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := decodeRequestV0(accepted.Frame, admittedAt)
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
	if _, err := decodeRequestV0(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unpaired surrogate after escaped quote accepted: %v", err)
	}
}

func TestValidateAdmittedRejectsUnknownVersion(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	record := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	record.Version = 1
	if err := validateAdmitted(record); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown admitted version accepted: %v", err)
	}
}

func TestObjectFieldsV0RejectsMalformed(t *testing.T) {
	tests := map[string][]byte{
		"non-object":    []byte(`[]`),
		"duplicate":     []byte(`{"x":0,"x":1}`),
		"missing value": []byte(`{"x":}`),
		"missing close": []byte(`{"x":0`),
		"trailing data": []byte(`{}x`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := objectFieldsV0(data); ok {
				t.Fatal("malformed v0 object decoded")
			}
		})
	}
}

func FuzzDecodeRequestV0(f *testing.F) {
	accepted, admittedAt := testAccepted(f)
	f.Add(accepted.Frame)
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, frame []byte) {
		request, err := decodeRequestV0(frame, admittedAt)
		if err != nil {
			return
		}
		if !validRequestV0(request, admittedAt) {
			t.Fatal("decoder accepted an invalid v0 request")
		}
		canonical, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal accepted v0 request: %v", err)
		}
		decoded, err := decodeRequestV0(canonical, admittedAt)
		if err != nil || decoded != request {
			t.Fatalf("canonical v0 request did not round trip: decoded=%+v error=%v", decoded, err)
		}
	})
}
