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
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func nilContext() context.Context {
	return nil
}

func TestOperationRejectsBeforeExecution(t *testing.T) {
	root := testEvidenceRoot(t)
	operation, err := New(testWorker(t), root)
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"not-a-url",
		urlreference.Defang,
	)
	if result.Status != Rejected {
		t.Fatalf("result=%+v", result)
	}
	result = operation.Execute(
		nilContext(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Rejected ||
		!errors.Is(result.Err, urladmission.ErrRejected) ||
		result.AttemptID != "" {
		t.Fatalf("nil context result=%+v", result)
	}
	entries, err := os.ReadDir(filepath.Join(root, "attempts", ".pending"))
	if err != nil {
		t.Fatalf("read pending attempts: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected request created evidence: %v", entries)
	}
}

func TestOperationDoesNotRejectAdmissionFailure(t *testing.T) {
	operation, err := New(testWorker(t), testEvidenceRoot(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admissionErr := errors.New("entropy unavailable")
	operation.admit = func(
		string,
		urlreference.Mode,
		time.Time,
	) (urladmission.Accepted, error) {
		return urladmission.Accepted{}, admissionErr
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Failed ||
		!errors.Is(result.Err, ErrAdmission) ||
		!errors.Is(result.Err, admissionErr) ||
		result.AttemptID != "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New("missing.exe", t.TempDir()); err == nil {
		t.Fatal("invalid worker accepted")
	}
	evidenceFile := filepath.Join(t.TempDir(), "evidence")
	if err := os.WriteFile(evidenceFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(testWorker(t), evidenceFile); err == nil {
		t.Fatal("invalid evidence root accepted")
	}
}

func TestOperationUsesContractLimits(t *testing.T) {
	limits := operationLimits()
	if limits.InputBytes != workerprotocol.MaxResponseBytes ||
		limits.OutputBytes != workerprotocol.MaxResponseBytes ||
		limits.ErrorBytes != workerprotocol.StderrBytes ||
		limits.MemoryBytes != workerprotocol.MemoryBytes ||
		limits.Processes != workerprotocol.Processes ||
		limits.StartupTimeout != containmentStartupTimeout ||
		limits.Timeout != time.Duration(workerprotocol.TimeoutMS)*time.Millisecond {
		t.Fatalf("limits=%+v", limits)
	}
}
