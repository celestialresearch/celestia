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

//go:build !windows || (windows && !amd64)

package urloperation

import (
	"context"
	"errors"
	"testing"

	"celestia.research/celestia/internal/processsupervision"
	"celestia.research/celestia/internal/urlreferencev1"
)

func TestOperationFailsClosed(t *testing.T) {
	if _, err := New("/worker", "/evidence"); !errors.Is(
		err,
		processsupervision.ErrUnavailable,
	) {
		t.Fatalf("constructor error=%v", err)
	}
	result := (&Operation{}).Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Failed ||
		!errors.Is(result.Err, processsupervision.ErrUnavailable) {
		t.Fatalf("result=%+v", result)
	}
}
