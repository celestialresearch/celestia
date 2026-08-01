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

package supervision_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/urladmission"
	"celestia.research/celestia/internal/urlreferencev1"
	"celestia.research/celestia/internal/workerprotocolv1"
	"golang.org/x/sys/windows"
)

func TestMain(testingMain *testing.M) {
	if os.Getenv("CELESTIA_TEST_WORKER") == "" ||
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER") == "" {
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
		binaryDirectory := filepath.Join(root, "target", "debug")
		fixtureDirectory := filepath.Join(root, "worker", "qualification-fixtures", "target", "debug")
		if err := os.Setenv(
			"CELESTIA_TEST_WORKER",
			filepath.Join(binaryDirectory, "celestia-url-reference.exe"),
		); err != nil {
			fmt.Fprintf(os.Stderr, "configure production worker: %v\n", err)
			os.Exit(1)
		}
		if err := os.Setenv(
			"CELESTIA_TEST_HOSTILE_WORKER",
			filepath.Join(fixtureDirectory, "celestia-hostile-worker.exe"),
		); err != nil {
			fmt.Fprintf(os.Stderr, "configure qualification worker: %v\n", err)
			os.Exit(1)
		}
		cancel()
	}
	os.Exit(testingMain.Run())
}

func TestSupervisorRunsWorker(t *testing.T) {
	worker := os.Getenv("CELESTIA_TEST_WORKER")
	if worker == "" {
		t.Fatal("CELESTIA_TEST_WORKER is not set")
	}
	supervisor, err := supervision.New(worker, testLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	accepted, err := urladmission.Admit(
		"https://example.test/path",
		urlreference.Defang,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("admit request: %v", err)
	}
	outcome := runTestSupervisor(supervisor, context.Background(), accepted.Frame)
	if outcome.Status != supervision.Completed {
		t.Fatalf("run worker: status=%s error=%v stderr=%q", outcome.Status, outcome.Err, outcome.Stderr)
	}
	if _, err := workerprotocol.DecodeResponse(outcome.Stdout, correlation(t, accepted), int(outcome.ExitCode)); err != nil {
		t.Fatalf("validate response: %v", err)
	}
	if !outcome.CleanupComplete {
		t.Fatal("worker cleanup was incomplete")
	}
}

func TestSupervisorAllowsProtocolExits(t *testing.T) {
	worker := os.Getenv("CELESTIA_TEST_WORKER")
	if worker == "" {
		t.Fatal("CELESTIA_TEST_WORKER is not set")
	}
	supervisor, err := supervision.New(worker, testLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	accepted, err := urladmission.Admit(
		"https://example.test/path",
		urlreference.Defang,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("admit request: %v", err)
	}
	t.Run("rejected", func(t *testing.T) {
		outcome := runTestSupervisor(
			supervisor,
			context.Background(),
			workerRejectedFrame(t, accepted),
		)
		if outcome.Status != supervision.Completed || outcome.ExitCode != 2 {
			t.Fatalf("status=%s exit=%d error=%v", outcome.Status, outcome.ExitCode, outcome.Err)
		}
		if _, err := workerprotocol.DecodeResponse(
			outcome.Stdout,
			correlation(t, accepted),
			int(outcome.ExitCode),
		); err != nil {
			t.Fatalf("decode rejected response: %v", err)
		}
	})
	t.Run("failed", func(t *testing.T) {
		outcome := runTestSupervisor(supervisor, context.Background(), []byte("{"))
		if outcome.Status != supervision.Completed || outcome.ExitCode != 3 {
			t.Fatalf("status=%s exit=%d error=%v", outcome.Status, outcome.ExitCode, outcome.Err)
		}
		_, err := workerprotocol.DecodeResponse(
			outcome.Stdout,
			correlation(t, accepted),
			int(outcome.ExitCode),
		)
		if !errors.Is(err, workerprotocol.ErrProtocol) {
			t.Fatalf("decode failed response error=%v, want protocol error", err)
		}
	})
}

func TestSupervisorEnforcesStreamsAndDeadline(t *testing.T) {
	worker := hostileWorker(t)
	tests := []struct {
		name    string
		frame   string
		status  supervision.Status
		timeout time.Duration
	}{
		{
			name:    "stdout",
			frame:   "stdout_overflow",
			status:  supervision.OutputOverflow,
			timeout: 2 * time.Second,
		},
		{
			name:    "stderr",
			frame:   "stderr_overflow",
			status:  supervision.ErrorOverflow,
			timeout: 2 * time.Second,
		},
		{
			name:    "timeout",
			frame:   "hang",
			status:  supervision.TimedOut,
			timeout: 500 * time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := testLimits()
			limits.Timeout = test.timeout
			outcome := runFixture(t, worker, limits, test.frame)
			if outcome.Status != test.status {
				t.Fatalf("status=%s error=%v", outcome.Status, outcome.Err)
			}
			if !outcome.CleanupComplete {
				t.Fatal("cleanup incomplete")
			}
		})
	}
}

func TestSupervisorBoundsBlockedInput(t *testing.T) {
	worker := filepath.Join(
		filepath.Dir(hostileWorker(t)),
		"celestia-blocked-input-worker.exe",
	)
	limits := testLimits()
	limits.InputBytes = 65_536
	outcome := runFixture(
		t,
		worker,
		limits,
		string(make([]byte, limits.InputBytes)),
	)
	maximumDuration := limits.StartupTimeout + limits.Timeout + limits.CleanupTimeout
	if outcome.Status != supervision.TimedOut ||
		!outcome.CleanupComplete ||
		outcome.Duration > maximumDuration {
		t.Fatalf(
			"status=%s cleanup=%t duration=%s error=%v",
			outcome.Status,
			outcome.CleanupComplete,
			outcome.Duration,
			outcome.Err,
		)
	}
}

func TestSupervisorDistinguishesFailures(t *testing.T) {
	worker := hostileWorker(t)
	tests := []struct {
		name   string
		frame  string
		status supervision.Status
	}{
		{name: "malformed output remains process success", frame: "malformed", status: supervision.Completed},
		{name: "partial output and crash", frame: "partial", status: supervision.ExitFailed},
		{name: "unsupported exit", frame: "unsupported", status: supervision.ExitFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := runFixture(t, worker, testLimits(), test.frame)
			if outcome.Status != test.status {
				t.Fatalf("status=%s error=%v", outcome.Status, outcome.Err)
			}
		})
	}
}

func TestSupervisorRejectsCancelledRequest(t *testing.T) {
	supervisor, err := supervision.New(hostileWorker(t), testLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome := runTestSupervisor(supervisor, ctx, []byte("hang"))
	if outcome.Status != supervision.Cancelled {
		t.Fatalf("status=%s error=%v", outcome.Status, outcome.Err)
	}
}

func TestSupervisorCancelsRunningWorker(t *testing.T) {
	limits := testLimits()
	limits.Timeout = 2 * time.Second
	supervisor, err := supervision.New(hostileWorker(t), limits)
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	outcome := runTestSupervisor(supervisor, ctx, []byte("hang"))
	if outcome.Status != supervision.Cancelled || !outcome.CleanupComplete {
		t.Fatalf("status=%s cleanup=%t error=%v", outcome.Status, outcome.CleanupComplete, outcome.Err)
	}
}

func TestSupervisorRejectsInvalidConfiguration(t *testing.T) {
	limits := testLimits()
	maximumInput := limits
	maximumInput.InputBytes = math.MaxInt
	maximumOutput := limits
	maximumOutput.OutputBytes = math.MaxInt
	maximumError := limits
	maximumError.ErrorBytes = math.MaxInt
	subTickTimeout := limits
	subTickTimeout.Timeout = time.Nanosecond
	tests := []struct {
		name   string
		worker string
		limits supervision.Limits
	}{
		{name: "empty path", limits: limits},
		{name: "relative path", worker: "worker.exe", limits: limits},
		{name: "zero limits", worker: hostileWorker(t)},
		{name: "missing worker", worker: filepath.Join(t.TempDir(), "missing.exe"), limits: limits},
		{name: "directory", worker: t.TempDir(), limits: limits},
		{name: "maximum input", worker: hostileWorker(t), limits: maximumInput},
		{name: "maximum output", worker: hostileWorker(t), limits: maximumOutput},
		{name: "maximum diagnostics", worker: hostileWorker(t), limits: maximumError},
		{name: "sub-tick process time", worker: hostileWorker(t), limits: subTickTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := supervision.New(test.worker, test.limits); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestSupervisorRejectsInvalidFrames(t *testing.T) {
	supervisor, err := supervision.New(hostileWorker(t), testLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	tests := []struct {
		name  string
		ctx   context.Context
		frame []byte
	}{
		{name: "nil context", frame: []byte("malformed")},
		{name: "empty frame", ctx: context.Background()},
		{
			name:  "oversized frame",
			ctx:   context.Background(),
			frame: make([]byte, testLimits().InputBytes+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := runTestSupervisor(supervisor, test.ctx, test.frame)
			if outcome.Status != supervision.StartFailed {
				t.Fatalf("status=%s error=%v", outcome.Status, outcome.Err)
			}
		})
	}
}

func TestSupervisorBlocksAmbientAuthority(t *testing.T) {
	worker := hostileWorker(t)
	t.Run("network", func(t *testing.T) {
		listener, err := (&net.ListenConfig{}).Listen(
			context.Background(),
			"tcp4",
			"127.0.0.1:0",
		)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer func() {
			if err := listener.Close(); err != nil {
				t.Errorf("close listener: %v", err)
			}
		}()
		limits := testLimits()
		limits.Timeout = 2 * time.Second
		outcome := runFixture(t, worker, limits, "network\n"+listener.Addr().String())
		assertDenied(t, outcome)
	})
	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "undeclared.txt")
		if err := os.WriteFile(path, []byte("not worker input"), 0o600); err != nil {
			t.Fatalf("write undeclared file: %v", err)
		}
		outcome := runFixture(t, worker, testLimits(), "file\n"+path)
		assertDenied(t, outcome)
	})
	t.Run("credentials", func(t *testing.T) {
		outcome := runFixture(t, worker, testLimits(), "credentials")
		assertDenied(t, outcome)
	})
	t.Run("child", func(t *testing.T) {
		outcome := runFixture(t, worker, testLimits(), "descendant")
		if outcome.Status != supervision.Completed || string(outcome.Stdout) != "blocked" {
			t.Fatalf("child was not blocked: status=%s stdout=%q error=%v", outcome.Status, outcome.Stdout, outcome.Err)
		}
	})
	t.Run("memory", func(t *testing.T) {
		outcome := runFixture(t, worker, testLimits(), "memory")
		if outcome.Status == supervision.Completed && string(outcome.Stdout) == "allowed" {
			t.Fatal("worker committed memory above its limit")
		}
		if !outcome.CleanupComplete {
			t.Fatalf("memory fixture cleanup failed: %v", outcome.Err)
		}
	})
}

func TestSupervisorCleansDescendant(t *testing.T) {
	assertDescendantCleaned(t, "descendant", 2)
}

func TestSupervisorCleansDescendantAfterParentExit(t *testing.T) {
	worker := hostileWorker(t)
	limits := testLimits()
	limits.Processes = 2
	outcome := runFixture(t, worker, limits, "descendant_exit")
	if outcome.Status == supervision.Completed &&
		strings.TrimSpace(string(outcome.Stdout)) == "blocked" &&
		outcome.CleanupComplete {
		return
	}
	if outcome.Status != supervision.Completed || !outcome.CleanupComplete {
		t.Fatalf(
			"status=%s cleanup=%t stdout=%q error=%v",
			outcome.Status,
			outcome.CleanupComplete,
			outcome.Stdout,
			outcome.Err,
		)
	}
	assertProcessExited(t, outcome.Stdout)
}

func TestSupervisorCleansGrandchild(t *testing.T) {
	assertDescendantCleaned(t, "grandchild", 3)
}

func assertDescendantCleaned(t *testing.T, mode string, processes uint32) {
	t.Helper()
	worker := hostileWorker(t)
	limits := testLimits()
	limits.Processes = processes
	limits.Timeout = 2 * time.Second
	outcome := runFixture(t, worker, limits, mode)
	if outcome.Status == supervision.Completed &&
		strings.TrimSpace(string(outcome.Stdout)) == "blocked" &&
		outcome.CleanupComplete {
		return
	}
	if outcome.Status != supervision.TimedOut {
		t.Fatalf("status=%s stdout=%q error=%v", outcome.Status, outcome.Stdout, outcome.Err)
	}
	assertProcessExited(t, outcome.Stdout)
}

func assertProcessExited(t *testing.T, output []byte) {
	t.Helper()
	pid, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
	if err != nil {
		t.Fatalf("parse descendant identity %q: %v", output, err)
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Fatalf("open descendant %d: %v", pid, err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("close descendant handle: %v", err)
		}
	}()
	event, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		t.Fatalf("inspect descendant %d: %v", pid, err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("descendant %d survived supervisor return", pid)
	}
}

func runFixture(
	t *testing.T,
	worker string,
	limits supervision.Limits,
	frame string,
) supervision.Outcome {
	t.Helper()
	supervisor, err := supervision.New(worker, limits)
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	return runTestSupervisor(supervisor, context.Background(), []byte(frame))
}

func runTestSupervisor(
	supervisor *supervision.Supervisor,
	ctx context.Context,
	frame []byte,
) supervision.Outcome {
	return supervisor.RunBefore(
		ctx,
		frame,
		time.Now().Add(testLimits().StartupTimeout),
	)
}

func assertDenied(t *testing.T, outcome supervision.Outcome) {
	t.Helper()
	if outcome.Status != supervision.Completed ||
		string(outcome.Stdout) != "denied" ||
		!outcome.CleanupComplete {
		t.Fatalf(
			"ambient authority not denied: status=%s stdout=%q error=%v",
			outcome.Status,
			outcome.Stdout,
			outcome.Err,
		)
	}
}

func hostileWorker(t *testing.T) string {
	t.Helper()
	value := os.Getenv("CELESTIA_TEST_HOSTILE_WORKER")
	if value == "" {
		t.Fatal("CELESTIA_TEST_HOSTILE_WORKER is not set")
	}
	return value
}

func repositoryRoot() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("read test working directory: %w", err)
	}
	root := filepath.Clean(filepath.Join(workingDirectory, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "Cargo.toml")); err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	return root, nil
}

func correlation(t *testing.T, accepted urladmission.Accepted) workerprotocol.Correlation {
	t.Helper()
	_, correlation, err := workerprotocol.DecodeRequest(
		accepted.Frame,
		admittedAt(t, accepted),
	)
	if err != nil {
		t.Fatalf("decode admitted request: %v", err)
	}
	return correlation
}

func admittedAt(t *testing.T, accepted urladmission.Accepted) time.Time {
	t.Helper()
	deadline, err := time.Parse(time.RFC3339Nano, accepted.Request.Deadline)
	if err != nil {
		t.Fatalf("parse admitted deadline: %v", err)
	}
	return deadline.Add(
		-time.Duration(workerprotocol.StartTimeoutMS) * time.Millisecond,
	)
}

func workerRejectedFrame(t *testing.T, accepted urladmission.Accepted) []byte {
	t.Helper()
	var request workerprotocol.Request
	if err := json.Unmarshal(accepted.Frame, &request); err != nil {
		t.Fatalf("decode accepted frame: %v", err)
	}
	input := "https://example[.]test/"
	hash := sha256.Sum256([]byte(input))
	request.Input = input
	request.InputLength = len(input)
	request.InputSHA256 = hex.EncodeToString(hash[:])
	frame, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode rejected frame: %v", err)
	}
	return frame
}

func testLimits() supervision.Limits {
	return supervision.Limits{
		InputBytes:     workerprotocol.MaxResponseBytes,
		OutputBytes:    8192,
		ErrorBytes:     8192,
		MemoryBytes:    workerprotocol.MemoryBytes,
		Processes:      workerprotocol.Processes,
		StartupTimeout: 10 * time.Second,
		Timeout:        500 * time.Millisecond,
		CleanupTimeout: time.Second,
	}
}
