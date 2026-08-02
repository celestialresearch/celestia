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

//go:build windows && amd64

package urloperation

import (
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"testing"
)

func BenchmarkOperation(b *testing.B) {
	operation, err := New(
		locateWorker(b, "celestia-url-reference.exe"),
		testEvidenceRoot(b),
	)
	if err != nil {
		b.Fatalf("new operation: %v", err)
	}
	b.ResetTimer()
	for range b.N {
		result := operation.Execute(
			context.Background(),
			"https://example.test/path",
			urlreference.Defang,
		)
		if result.Status != Verified {
			b.Fatalf("status=%s error=%v", result.Status, result.Err)
		}
	}
}
