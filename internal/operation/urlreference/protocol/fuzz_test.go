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
	"encoding/json"
	"testing"
)

func FuzzDecodeResponse(f *testing.F) {
	request := testRequest()
	correlation := testCorrelation(f, request)
	f.Add([]byte(validResponseJSON(f, request)), 0)
	f.Add([]byte(`{}`), 0)
	f.Add([]byte(`{"a":[{"b":1}]}`), 0)

	f.Fuzz(func(t *testing.T, data []byte, exitCode int) {
		response, err := decodeResponse(data, correlation, exitCode)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("marshal accepted response: %v", err)
		}
		if _, err := decodeResponse(encoded, correlation, exitCode); err != nil {
			t.Fatalf("round-trip response rejected: %v", err)
		}
	})
}
func FuzzDecodeRequest(f *testing.F) {
	valid, err := EncodeRequest(testRequest(), testAdmittedAt())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"protocol_version":-0}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		request, err := DecodeRequest(data, testAdmittedAt())
		if err != nil {
			return
		}
		encoded, err := EncodeRequest(request, testAdmittedAt())
		if err != nil {
			t.Fatalf("encode accepted request: %v", err)
		}
		if _, err := DecodeRequest(encoded, testAdmittedAt()); err != nil {
			t.Fatalf("round-trip request rejected: %v", err)
		}
	})
}
