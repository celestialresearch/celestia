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

package processsupervision_test

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

	"celestia.research/governed-operation/internal/processsupervision"
	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/urlreference"
	"celestia.research/governed-operation/internal/workerprotocol"
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
			fmt.Fprintf(os.Stderr, "build production worker: %v\n", err)
			os.Exit(1)
		}
		// The test invokes the repository-pinned Cargo tool with fixed arguments;
		// the path is derived only from the checked-out repository root.
		qualification := exec.CommandContext( //nolint:gosec // fixed test-tool invocation
			ctx,
			"cargo",
			"build",
			"--manifest-path",
			filepath.Join(root, "worker", "qualification-fixtures", "Cargo.toml"),
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
	}
	os.Exit(testingMain.Run())
}

func TestSupervisorRunsWorker(t *testing.T) {
	worker := os.Getenv("CELESTIA_TEST_WORKER")
	if worker == "" {
		t.Fatal("CELESTIA_TEST_WORKER is not set")
	}
	supervisor, err := processsupervision.New(worker, testLimits())
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
	outcome := supervisor.Run(context.Background(), accepted.Frame)
	if outcome.Status != processsupervision.Completed {
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
	supervisor, err := processsupervision.New(worker, testLimits())
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
		outcome := supervisor.Run(
			context.Background(),
			workerRejectedFrame(t, accepted),
		)
		if outcome.Status != processsupervision.Completed || outcome.ExitCode != 2 {
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
		outcome := supervisor.Run(context.Background(), []byte("{"))
		if outcome.Status != processsupervision.Completed || outcome.ExitCode != 3 {
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
		status  processsupervision.Status
		timeout time.Duration
	}{
		{
			name:    "stdout",
			frame:   "stdout_overflow",
			status:  processsupervision.OutputOverflow,
			timeout: 2 * time.Second,
		},
		{
			name:    "stderr",
			frame:   "stderr_overflow",
			status:  processsupervision.ErrorOverflow,
			timeout: 2 * time.Second,
		},
		{
			name:    "timeout",
			frame:   "hang",
			status:  processsupervision.TimedOut,
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
	started := time.Now()
	outcome := runFixture(
		t,
		worker,
		limits,
		string(make([]byte, limits.InputBytes)),
	)
	if outcome.Status != processsupervision.TimedOut ||
		!outcome.CleanupComplete ||
		time.Since(started) > 2*time.Second {
		t.Fatalf(
			"status=%s cleanup=%t duration=%s error=%v",
			outcome.Status,
			outcome.CleanupComplete,
			time.Since(started),
			outcome.Err,
		)
	}
}

func TestSupervisorDistinguishesFailures(t *testing.T) {
	worker := hostileWorker(t)
	tests := []struct {
		name   string
		frame  string
		status processsupervision.Status
	}{
		{name: "malformed output remains process success", frame: "malformed", status: processsupervision.Completed},
		{name: "partial output and crash", frame: "partial", status: processsupervision.ExitFailed},
		{name: "unsupported exit", frame: "unsupported", status: processsupervision.ExitFailed},
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
	supervisor, err := processsupervision.New(hostileWorker(t), testLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome := supervisor.Run(ctx, []byte("hang"))
	if outcome.Status != processsupervision.Cancelled {
		t.Fatalf("status=%s error=%v", outcome.Status, outcome.Err)
	}
}

func TestSupervisorCancelsRunningWorker(t *testing.T) {
	limits := testLimits()
	limits.Timeout = 2 * time.Second
	supervisor, err := processsupervision.New(hostileWorker(t), limits)
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	outcome := supervisor.Run(ctx, []byte("hang"))
	if outcome.Status != processsupervision.Cancelled || !outcome.CleanupComplete {
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
		limits processsupervision.Limits
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
			if _, err := processsupervision.New(test.worker, test.limits); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestSupervisorRejectsInvalidFrames(t *testing.T) {
	supervisor, err := processsupervision.New(hostileWorker(t), testLimits())
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
			outcome := supervisor.Run(test.ctx, test.frame)
			if outcome.Status != processsupervision.StartFailed {
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
		if outcome.Status != processsupervision.Completed || string(outcome.Stdout) != "blocked" {
			t.Fatalf("child was not blocked: status=%s stdout=%q error=%v", outcome.Status, outcome.Stdout, outcome.Err)
		}
	})
	t.Run("memory", func(t *testing.T) {
		outcome := runFixture(t, worker, testLimits(), "memory")
		if outcome.Status == processsupervision.Completed && string(outcome.Stdout) == "allowed" {
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
	if outcome.Status == processsupervision.Completed &&
		strings.TrimSpace(string(outcome.Stdout)) == "blocked" &&
		outcome.CleanupComplete {
		t.Fatal("host denied child creation; cleanup path was not exercised")
	}
	if outcome.Status != processsupervision.TimedOut {
		t.Fatalf("status=%s stdout=%q error=%v", outcome.Status, outcome.Stdout, outcome.Err)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(outcome.Stdout)), 10, 32)
	if err != nil {
		t.Fatalf("parse descendant identity %q: %v", outcome.Stdout, err)
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
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
	limits processsupervision.Limits,
	frame string,
) processsupervision.Outcome {
	t.Helper()
	supervisor, err := processsupervision.New(worker, limits)
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	return supervisor.Run(context.Background(), []byte(frame))
}

func assertDenied(t *testing.T, outcome processsupervision.Outcome) {
	t.Helper()
	if outcome.Status != processsupervision.Completed ||
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
	root := filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "Cargo.toml")); err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	return root, nil
}

func correlation(t *testing.T, accepted urladmission.Accepted) workerprotocol.Correlation {
	t.Helper()
	_, correlation, err := workerprotocol.DecodeRequest(accepted.Frame, admittedAt(accepted))
	if err != nil {
		t.Fatalf("decode admitted request: %v", err)
	}
	return correlation
}

func admittedAt(accepted urladmission.Accepted) time.Time {
	deadline, _ := time.Parse(time.RFC3339Nano, accepted.Request.Deadline)
	return deadline.Add(-time.Duration(workerprotocol.TimeoutMS) * time.Millisecond)
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

func testLimits() processsupervision.Limits {
	return processsupervision.Limits{
		InputBytes:     workerprotocol.MaxResponseBytes,
		OutputBytes:    8192,
		ErrorBytes:     8192,
		MemoryBytes:    workerprotocol.MemoryBytes,
		Processes:      workerprotocol.Processes,
		StartupTimeout: 2 * time.Second,
		Timeout:        500 * time.Millisecond,
		CleanupTimeout: time.Second,
	}
}
