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

package urloperation

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"celestia.research/governed-operation/internal/processsupervision"
	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/urlreference"
	"celestia.research/governed-operation/internal/workerprotocol"
)

func TestMain(testingMain *testing.M) {
	root, err := repositoryRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"cargo",
		"build",
		"--workspace",
		"--all-targets",
		"--locked",
	)
	command.Dir = root
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build worker fixtures: %v\n", err)
		os.Exit(1)
	}
	os.Exit(testingMain.Run())
}

func TestOperationVerifiesWorker(t *testing.T) {
	worker := testWorker(t)
	operation, err := newTestOperation(t, worker)
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test/path",
		urlreference.Defang,
	)
	if result.Status != Verified ||
		result.Response == nil ||
		!result.Verification.Matched ||
		result.Verification.Expected != "hxxps://example[.]test/path" {
		t.Fatalf("result=%+v", result)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect attempt: %v", err)
	}
	if records.Observation == nil ||
		records.Observation.TerminalStatus != string(Verified) ||
		!records.Observation.VerificationPass {
		t.Fatalf("records=%+v", records)
	}
}

func TestOperationRejectsBeforeExecution(t *testing.T) {
	root := filepath.Join(t.TempDir(), "evidence")
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
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read evidence root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected request created evidence: %v", entries)
	}
}

func TestOperationReportsStagingFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "evidence")
	operation, err := New(testWorker(t), root)
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatalf("remove evidence root: %v", err)
	}
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("replace evidence root: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Indeterminate {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New("missing.exe", t.TempDir()); err == nil {
		t.Fatal("invalid worker accepted")
	}
}

func TestObservationPreservesProcessFailure(t *testing.T) {
	result := Result{
		Status:    Failed,
		AttemptID: "attempt",
		Process: processsupervision.Outcome{
			Status: processsupervision.ExitFailed,
			Err:    context.Canceled,
		},
		Err: ErrProtocol,
	}
	observation := observationFrom(result)
	if observation.ProtocolStatus != "invalid" ||
		observation.ProcessError == "" ||
		observation.TerminalStatus != string(Failed) {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestOperationRejectsProcessFailure(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted := admittedFixture(t, admittedAt)
	accepted.Frame = []byte("partial")
	result := operation.executeAccepted(context.Background(), accepted, admittedAt)
	if result.Status != Failed || result.Process.Status != processsupervision.ExitFailed {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationPreservesTermination(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	tests := []struct {
		name       string
		admittedAt time.Time
		context    func() context.Context
		status     Status
	}{
		{
			name:       "admitted deadline",
			admittedAt: time.Now().UTC().Add(-3 * time.Second),
			context:    context.Background,
			status:     TimedOut,
		},
		{
			name:       "caller cancellation",
			admittedAt: time.Now().UTC(),
			context: func() context.Context {
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				return cancelled
			},
			status: Cancelled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accepted := admittedFixture(t, test.admittedAt)
			result := operation.executeAccepted(
				test.context(),
				accepted,
				test.admittedAt,
			)
			if result.Status != test.status {
				t.Fatalf("status=%s process=%s error=%v", result.Status, result.Process.Status, result.Err)
			}
		})
	}
}

func TestOperationRejectsInvalidContext(t *testing.T) {
	if _, _, err := admittedContext(
		nilContext(),
		time.Now().UTC().Format(time.RFC3339Nano),
	); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, _, err := admittedContext(context.Background(), "invalid"); err == nil {
		t.Fatal("invalid deadline accepted")
	}
}

func nilContext() context.Context {
	return nil
}

func TestOperationUsesContractLimits(t *testing.T) {
	limits := operationLimits()
	if limits.InputBytes != workerprotocol.MaxResponseBytes ||
		limits.OutputBytes != workerprotocol.MaxResponseBytes ||
		limits.ErrorBytes != workerprotocol.StderrBytes ||
		limits.MemoryBytes != workerprotocol.MemoryBytes ||
		limits.Processes != workerprotocol.Processes ||
		limits.Timeout != time.Duration(workerprotocol.TimeoutMS)*time.Millisecond {
		t.Fatalf("limits=%+v", limits)
	}
}

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
	if result.Status != Failed || result.Process.Status != processsupervision.ExitFailed {
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

func TestOperationRejectsMalformedProtocol(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted := admittedFixture(t, admittedAt)
	accepted.Frame = []byte("malformed")
	result := operation.executeAccepted(context.Background(), accepted, admittedAt)
	if result.Status != Failed || result.Process.Status != processsupervision.Completed {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationPublishesProtocolFailure(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://malformed.test",
		urlreference.Defang,
	)
	if result.Status != Failed || result.Process.Status != processsupervision.Completed {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationRejectsSemanticLie(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != ExecutedUnverified ||
		result.Response == nil ||
		result.Verification.Matched {
		t.Fatalf("result=%+v", result)
	}
}

func admittedFixture(t *testing.T, admittedAt time.Time) urladmission.Accepted {
	t.Helper()
	accepted, err := urladmission.Admit(
		"https://example.test",
		urlreference.Defang,
		admittedAt,
	)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	return accepted
}

func newTestOperation(t *testing.T, worker string) (*Operation, error) {
	t.Helper()
	return New(worker, filepath.Join(t.TempDir(), "evidence"))
}

func testWorker(t *testing.T) string {
	t.Helper()
	return locateWorker(t, "celestia-url-reference.exe")
}

func testHostileWorker(t *testing.T) string {
	t.Helper()
	return locateWorker(t, "celestia-hostile-worker.exe")
}

func locateWorker(tb testing.TB, name string) string {
	tb.Helper()
	root := filepath.Clean(filepath.Join(testWorkingDirectory(tb), "..", ".."))
	path := filepath.Join(root, "target", "debug", name)
	if _, err := os.Stat(path); err != nil {
		tb.Fatalf("worker %s is unavailable: %v", name, err)
	}
	return path
}

func testWorkingDirectory(tb testing.TB) string {
	tb.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		tb.Fatalf("working directory: %v", err)
	}
	return workingDirectory
}

func repositoryRoot() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("working directory: %w", err)
	}
	return filepath.Clean(filepath.Join(workingDirectory, "..", "..")), nil
}

func BenchmarkOperation(b *testing.B) {
	operation, err := New(
		locateWorker(b, "celestia-url-reference.exe"),
		filepath.Join(b.TempDir(), "evidence"),
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
