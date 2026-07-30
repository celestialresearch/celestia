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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"celestia.research/governed-operation/internal/attemptstore"
	"celestia.research/governed-operation/internal/processsupervision"
	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/urlreferencev1"
	"celestia.research/governed-operation/internal/workerprotocolv1"
	"golang.org/x/sys/windows"
)

func TestMain(testingMain *testing.M) {
	root, err := repositoryRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
		fmt.Fprintf(os.Stderr, "build production worker: %v\n", err)
		os.Exit(1)
	}
	qualification := exec.CommandContext(
		ctx,
		"cargo",
		"build",
		"--manifest-path",
		"worker/qualification-fixtures/Cargo.toml",
		"--bins",
		"--locked",
	)
	qualification.Dir = root
	qualification.Stdout = os.Stderr
	qualification.Stderr = os.Stderr
	if err := qualification.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build qualification fixtures: %v\n", err)
		os.Exit(1)
	}
	cancel()
	os.Exit(testingMain.Run())
}

func TestOperationVerifiesWorker(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		mode     urlreference.Mode
		expected string
	}{
		{
			name:     "defang",
			input:    "https://example.test/path",
			mode:     urlreference.Defang,
			expected: "hxxps://example[.]test/path",
		},
		{
			name:     "fang",
			input:    "hxxps://example[.]test/path",
			mode:     urlreference.Fang,
			expected: "https://example.test/path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertVerifiedWorker(t, test.input, test.mode, test.expected)
		})
	}
}

func assertVerifiedWorker(t *testing.T, input string, mode urlreference.Mode, expected string) {
	t.Helper()

	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(context.Background(), input, mode)
	if result.Status != Verified ||
		result.Response == nil ||
		!result.Verification.Matched ||
		result.Verification.Expected != expected ||
		result.Response.Output == nil ||
		*result.Response.Output != expected {
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

func TestOperationReportsStagingFailure(t *testing.T) {
	root := testEvidenceRoot(t)
	operation, err := New(testWorker(t), root)
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	if err := os.RemoveAll(root); err != nil {
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
	if result.Status != Indeterminate || result.AttemptID != "" {
		t.Fatalf("result=%+v", result)
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
	observation := observationFrom(result, result.Process)
	if observation.ProtocolStatus != protocolNotRun ||
		observation.ProcessError == "" ||
		observation.TerminalStatus != string(Failed) {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestObservationMapsProtocolState(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		expected string
	}{
		{name: "not run", result: Result{}, expected: protocolNotRun},
		{
			name: "valid",
			result: Result{
				Response: &workerprotocol.Response{},
			},
			expected: protocolValid,
		},
		{
			name: "rejected",
			result: Result{
				Process: processsupervision.Outcome{
					Status: processsupervision.Completed,
				},
				Err: ErrProtocol,
			},
			expected: protocolRejected,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := observationFrom(test.result, test.result.Process).ProtocolStatus; actual != test.expected {
				t.Fatalf("status=%q, want %q", actual, test.expected)
			}
		})
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
	result, _ := operation.executeAccepted(context.Background(), accepted, admittedAt)
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
			admittedAt: time.Now().UTC().Add(-13 * time.Second),
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
			result, _ := operation.executeAccepted(
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

func TestOperationPublishesCallerDeadline(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted := admittedFixture(t, admittedAt)
	attempt, err := operation.store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	process := processsupervision.Outcome{
		Status:          processsupervision.Cancelled,
		Err:             context.DeadlineExceeded,
		CleanupComplete: true,
		Duration:        time.Nanosecond,
	}
	result := Result{
		AttemptID: accepted.Request.AttemptID,
		Status:    terminalStatus(process),
		Process:   callerProcess(process),
		Err:       errors.Join(ErrProcess, process.Err),
	}
	if err := attempt.Publish(observationFrom(result, process)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil ||
		records.Observation.ProcessStatus != string(processsupervision.Cancelled) ||
		records.Observation.TerminalStatus != string(TimedOut) {
		t.Fatalf("records=%+v", records)
	}
}

func TestTerminalStatusPreservesPrimaryOutcomeDuringCleanupFailure(t *testing.T) {
	tests := []struct {
		status processsupervision.Status
		err    error
		want   Status
	}{
		{status: processsupervision.TimedOut, err: context.DeadlineExceeded, want: TimedOut},
		{status: processsupervision.Cancelled, err: context.Canceled, want: Cancelled},
		{status: processsupervision.ExitFailed, err: errors.New("process failed"), want: Failed},
		{status: processsupervision.Completed, err: errors.New("cleanup failed"), want: Failed},
	}
	for _, test := range tests {
		process := processsupervision.Outcome{
			Status:          test.status,
			CleanupComplete: false,
			Err:             test.err,
		}
		if got := terminalStatus(process); got != test.want {
			t.Fatalf("status=%s terminal=%s want=%s", test.status, got, test.want)
		}
	}
}

func TestOperationRejectsInvalidContext(t *testing.T) {
	if _, err := admittedStartDeadline(
		nilContext(),
		time.Now().UTC().Format(time.RFC3339Nano),
	); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := admittedStartDeadline(context.Background(), "invalid"); err == nil {
		t.Fatal("invalid deadline accepted")
	}
}

func TestOperationRejectsInvalidAcceptedDeadline(t *testing.T) {
	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted := admittedFixture(t, admittedAt)
	accepted.Request.Deadline = "invalid"
	result, process := operation.executeAccepted(
		context.Background(),
		accepted,
		admittedAt,
	)
	if result.Status != Failed ||
		!errors.Is(result.Err, ErrProtocol) ||
		process.Status != "" {
		t.Fatalf("result=%+v process=%+v", result, process)
	}
}

func TestEvaluateResponseRejectsInvalidVerificationInputs(t *testing.T) {
	t.Parallel()

	accepted := admittedFixture(t, time.Now().UTC())
	process := processsupervision.Outcome{
		Status:          processsupervision.Completed,
		CleanupComplete: true,
	}
	result := evaluateResponse(accepted, process, workerprotocol.Response{
		Status: workerprotocol.Completed,
	})
	if result.Status != ExecutedUnverified ||
		!errors.Is(result.Err, ErrVerification) {
		t.Fatalf("missing output result=%+v", result)
	}

	output := "unused"
	accepted.Request.Input = "invalid"
	result = evaluateResponse(accepted, process, workerprotocol.Response{
		Status: workerprotocol.Completed,
		Output: &output,
	})
	if result.Status != ExecutedUnverified ||
		!errors.Is(result.Err, ErrVerification) {
		t.Fatalf("invalid admitted input result=%+v", result)
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
		limits.StartupTimeout != containmentStartupTimeout ||
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
	result, _ := operation.executeAccepted(context.Background(), accepted, admittedAt)
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

func TestOperationRecordsValidWorkerFailure(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		status        workerprotocol.Status
		processStatus processsupervision.Status
		exitCode      uint32
	}{
		{
			name:          "rejected",
			input:         "https://rejected.test",
			status:        workerprotocol.Rejected,
			processStatus: processsupervision.Completed,
			exitCode:      2,
		},
		{
			name:          "failed",
			input:         "https://failed.test",
			status:        workerprotocol.Failed,
			processStatus: processsupervision.ExitFailed,
			exitCode:      3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation, err := newTestOperation(t, testHostileWorker(t))
			if err != nil {
				t.Fatalf("new operation: %v", err)
			}
			result := operation.Execute(
				context.Background(),
				test.input,
				urlreference.Defang,
			)
			assertWorkerFailure(t, result, test.status)
			records, err := operation.store.Inspect(result.AttemptID)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			assertWorkerFailureEvidence(t, records, test.processStatus, test.exitCode)
		})
	}
}

func assertWorkerFailure(t *testing.T, result Result, status workerprotocol.Status) {
	t.Helper()
	if result.Status != Failed ||
		result.Process.Status != processsupervision.Completed ||
		len(result.Process.Stdout) != 0 ||
		len(result.Process.Stderr) != 0 ||
		result.Response == nil ||
		result.Response.Status != status {
		t.Fatalf("result=%+v", result)
	}
	assertProjectedDiagnostics(t, result)
}

func assertProjectedDiagnostics(t *testing.T, result Result) {
	t.Helper()
	if result.Response == nil ||
		len(result.Response.Diagnostics) != 0 ||
		len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != "worker_failure" ||
		result.Diagnostics[0].Message != "The worker reported a failure" ||
		result.Verification.VerifierID != "" {
		t.Fatalf("result=%+v", result)
	}
	if result.Diagnostics[0].Code == "fixture_rejected" ||
		result.Diagnostics[0].Code == "fixture_failed" {
		t.Fatalf("worker-controlled code exposed: %+v", result.Diagnostics)
	}
	if strings.Contains(result.Diagnostics[0].Message, "hostile fixture") {
		t.Fatalf("worker-controlled message exposed: %+v", result.Diagnostics)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), "hostile fixture") {
		t.Fatalf("raw worker evidence retained in result")
	}
}

func TestProjectDiagnostics(t *testing.T) {
	tests := []struct {
		name    string
		status  workerprotocol.Status
		worker  string
		code    string
		message string
		count   int
	}{
		{
			name:    "known rejection",
			status:  workerprotocol.Rejected,
			worker:  "invalid_reference",
			code:    "invalid_reference",
			message: "The worker rejected the URL reference",
			count:   1,
		},
		{
			name:    "unknown failure",
			status:  workerprotocol.Failed,
			worker:  "worker_selected_code",
			code:    "worker_failure",
			message: "The worker reported a failure",
			count:   1,
		},
		{
			name:   "completed",
			status: workerprotocol.Completed,
			worker: "invalid_reference",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics := projectDiagnostics(
				test.status,
				[]workerprotocol.Diagnostic{{
					Code:    test.worker,
					Message: "worker-controlled message",
				}},
			)
			if len(diagnostics) != test.count {
				t.Fatalf("diagnostics=%+v", diagnostics)
			}
			if test.count == 0 {
				return
			}
			if diagnostics[0].Code != test.code ||
				diagnostics[0].Message != test.message {
				t.Fatalf("diagnostics=%+v", diagnostics)
			}
		})
	}
}

func assertWorkerFailureEvidence(
	t *testing.T,
	records attemptstore.Records,
	processStatus processsupervision.Status,
	exitCode uint32,
) {
	t.Helper()
	if records.Observation == nil ||
		records.Observation.ProcessStatus != string(processStatus) ||
		records.Observation.ExitCode != exitCode ||
		records.Observation.ProtocolStatus != protocolValid ||
		records.Observation.VerificationID != "" ||
		records.Observation.TerminalStatus != string(Failed) {
		t.Fatalf("records=%+v", records)
	}
	if processStatus == processsupervision.ExitFailed &&
		records.Observation.ProcessError == "" {
		t.Fatalf("failed worker omitted process error: %+v", records.Observation)
	}
	if processStatus == processsupervision.Completed &&
		records.Observation.ProcessError != "" {
		t.Fatalf("rejected worker recorded process error: %+v", records.Observation)
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

func TestExecuteRecordsPublicationFailure(t *testing.T) {
	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	failure := errors.Join(attemptstore.ErrPublication, errors.New("write fixture"))
	operation.publish = func(
		attempt *attemptstore.Attempt,
		_ attemptstore.Observation,
	) error {
		return errors.Join(failure, attempt.Close())
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Indeterminate ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, failure) {
		t.Fatalf("result=%+v", result)
	}
}

func TestCancellationRacingPublicationPreservesOutcome(t *testing.T) {
	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	reached := make(chan struct{})
	resume := make(chan struct{})
	var resumeOnce sync.Once
	releasePublication := func() {
		resumeOnce.Do(func() {
			close(resume)
		})
	}
	defer releasePublication()
	operation.publish = func(
		attempt *attemptstore.Attempt,
		observation attemptstore.Observation,
	) error {
		close(reached)
		<-resume
		return attempt.Publish(observation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resultChannel := make(chan Result, 1)
	go func() {
		resultChannel <- operation.Execute(
			ctx,
			"https://example.test",
			urlreference.Defang,
		)
	}()
	select {
	case <-reached:
	case <-ctx.Done():
		t.Fatalf("execution did not reach publication: %v", ctx.Err())
	}
	cancel()
	releasePublication()
	var result Result
	select {
	case result = <-resultChannel:
	case <-time.After(30 * time.Second):
		t.Fatal("execution did not return after publication")
	}
	if result.Status != Verified {
		t.Fatalf("result=%+v", result)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect result: %v", err)
	}
	if records.Observation == nil ||
		records.Observation.TerminalStatus != string(Verified) {
		t.Fatalf("records=%+v", records)
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
	return New(worker, testEvidenceRoot(t))
}

func testEvidenceRoot(tb testing.TB) string {
	tb.Helper()
	parent := filepath.Join(tb.TempDir(), "owned")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		tb.Fatalf("current user: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)", user.User.Sid, user.User.Sid),
	)
	if err != nil {
		tb.Fatalf("evidence parent descriptor: %v", err)
	}
	pointer, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		tb.Fatalf("evidence parent path: %v", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pointer, &attributes); err != nil {
		tb.Fatalf("create evidence parent: %v", err)
	}
	return filepath.Join(parent, "evidence")
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
	binaryDirectory := filepath.Join(root, "target", "debug")
	if name == "celestia-hostile-worker.exe" || name == "celestia-blocked-input-worker.exe" {
		binaryDirectory = filepath.Join(root, "worker", "qualification-fixtures", "target", "debug")
	}
	path := filepath.Join(binaryDirectory, name)
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

func TestPublishReleaseFailurePreservesTerminalStatus(t *testing.T) {
	result := Result{Status: Verified}
	applyPublishError(&result, attemptstore.ErrRelease)
	if result.Status != Verified {
		t.Fatalf("release failure changed status to %q", result.Status)
	}
	if !errors.Is(result.Err, ErrCleanup) ||
		!errors.Is(result.Err, attemptstore.ErrRelease) {
		t.Fatalf("release failure not reported: %v", result.Err)
	}
	if errors.Is(result.Err, ErrPersistence) {
		t.Fatalf("release failure reported as persistence failure: %v", result.Err)
	}
}

func TestPublicationFailureOverridesReleaseFailure(t *testing.T) {
	result := Result{Status: Verified}
	applyPublishError(
		&result,
		errors.Join(attemptstore.ErrPublication, attemptstore.ErrRelease),
	)
	if result.Status != Indeterminate ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, ErrCleanup) {
		t.Fatalf("combined publication result=%+v", result)
	}
}

func TestUnexpectedPublishErrorIsIndeterminate(t *testing.T) {
	unexpected := errors.New("unexpected publication error")
	result := Result{Status: Verified}
	applyPublishError(&result, unexpected)
	if result.Status != Indeterminate ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, unexpected) {
		t.Fatalf("result=%+v", result)
	}
}

func TestUnknownProcessStatusFails(t *testing.T) {
	if status := terminalStatus(processsupervision.Outcome{}); status != Failed {
		t.Fatalf("terminal status=%q, want %q", status, Failed)
	}
	process := processsupervision.Outcome{
		Status: processsupervision.StartFailed,
		Err:    errors.New("native start failure"),
	}
	if status := terminalStatus(process); status != Failed {
		t.Fatalf("start failure terminal status=%q, want %q", status, Failed)
	}
}

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
