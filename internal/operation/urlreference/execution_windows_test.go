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
	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"errors"
	"testing"
)

func TestOperationPublishesProcessFailure(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://partial.test",
		urlreference.Defang,
	)
	if result.Status != Failed || result.Process.Status != supervision.ExitFailed {
		t.Fatalf("result=%+v", result)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil || records.Observation.TerminalStatus != string(Failed) {
		t.Fatalf("records=%+v", records)
	}
}

func TestUnknownProcessStatusFails(t *testing.T) {
	if status := terminalStatus(supervision.Outcome{}); status != Failed {
		t.Fatalf("terminal status=%q, want %q", status, Failed)
	}
	process := supervision.Outcome{
		Status: supervision.StartFailed,
		Err:    errors.New("native start failure"),
	}
	if status := terminalStatus(process); status != Failed {
		t.Fatalf("start failure terminal status=%q, want %q", status, Failed)
	}
}
