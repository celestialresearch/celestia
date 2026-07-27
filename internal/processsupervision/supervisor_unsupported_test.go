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

package processsupervision

import (
	"context"
	"errors"
	"testing"
)

func TestSupervisorFailsClosed(t *testing.T) {
	if _, err := New("/worker", Limits{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("constructor error=%v", err)
	}
	outcome := (&Supervisor{}).Run(context.Background(), []byte("request"))
	if outcome.Status != StartFailed || !errors.Is(outcome.Err, ErrUnavailable) {
		t.Fatalf("outcome=%+v", outcome)
	}
}
