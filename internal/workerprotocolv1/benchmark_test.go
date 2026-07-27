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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func BenchmarkDecodeResponse(b *testing.B) {
	output := "hxxps://example[.]test/"
	hash := sha256.Sum256([]byte(output))
	response, err := json.Marshal(Response{
		ProtocolVersion:  ProtocolVersion,
		OperationID:      OperationID,
		OperationVersion: OperationVersion,
		AttemptID:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		RequestNonce:     "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		WorkerID:         WorkerID,
		WorkerVersion:    WorkerVersion,
		Status:           Completed,
		OutputMediaType:  new(MediaType),
		OutputLength:     new(len(output)),
		OutputSHA256:     new(hex.EncodeToString(hash[:])),
		Output:           new(output),
		Diagnostics:      []Diagnostic{},
		DurationNS:       1,
	})
	if err != nil {
		b.Fatalf("encode response: %v", err)
	}
	correlation := Correlation{
		attemptID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		nonce:     "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		mediaType: MediaType,
	}
	b.ResetTimer()
	for range b.N {
		if _, err := DecodeResponse(response, correlation, 0); err != nil {
			b.Fatalf("decode response: %v", err)
		}
	}
}
