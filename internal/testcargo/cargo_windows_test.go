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

package testcargo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cargoHelperMode = "CELESTIA_TEST_CARGO_HELPER"

var testEventID atomic.Uint64

func TestBuild(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		if err := testBuild(t, context.Background(), "success", "", "", ""); err != nil {
			t.Fatalf("run helper: %v", err)
		}
	})
	t.Run("expired deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
		defer cancel()
		if err := testBuild(t, ctx, "success", "", "", ""); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("run helper error = %v", err)
		}
	})
}

func TestBuildRejectsContextWithoutDeadline(t *testing.T) {
	err := Build(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "context lacks deadline") {
		t.Fatalf("missing deadline error = %v", err)
	}
}

func TestWaitCause(t *testing.T) {
	if cause := waitCause(context.Background(), uint32(windows.WAIT_TIMEOUT)); !errors.Is(cause, context.DeadlineExceeded) {
		t.Fatalf("deadline wait cause = %v", cause)
	}
	if cause := waitCause(context.Background(), windows.WAIT_OBJECT_0); cause != nil {
		t.Fatalf("completed wait cause = %v", cause)
	}
}

func TestNextProcessListSize(t *testing.T) {
	current, err := nextProcessListSize(0, 1, 0)
	if err != nil {
		t.Fatalf("initial process list size: %v", err)
	}
	next, err := nextProcessListSize(current, 2, 1)
	if err != nil || next <= current {
		t.Fatalf("resize process list = %d, %v", next, err)
	}
	if next, err := nextProcessListSize(next, 2, 2); err != nil || next != 0 {
		t.Fatalf("complete process list = %d, %v", next, err)
	}
	if _, err := nextProcessListSize(current, 1, 2); err == nil {
		t.Fatal("invalid process list accepted")
	}
}

func TestBuildCancelsDescendant(t *testing.T) {
	event, name, closeEvent := testEvent(t)
	defer closeEvent()
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- testBuild(t, ctx, "wait", pidPath, name, "")
	}()
	if event, err := windows.WaitForSingleObject(event, 10_000); err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("wait for helper: event=%d error=%v", event, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel build error = %v", err)
	}
	assertDescendantExited(t, pidPath)
}

func TestBuildRejectsLiveDescendant(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	err := testBuild(t, context.Background(), "exit", pidPath, "", "")
	if err == nil || !strings.Contains(err.Error(), "cargo exited with a running descendant") {
		t.Fatalf("clean parent build error = %v", err)
	}
	assertDescendantExited(t, pidPath)
}

func TestJoinTreeTerminatesAfterObservationFailure(t *testing.T) {
	cases := []struct {
		name string
		wait treeWaiter
	}{
		{
			name: "graceful observation",
			wait: func(context.Context, windows.Handle, windows.Handle, time.Duration, bool) (bool, error) {
				return false, errInjectedTreeObservation
			},
		},
		{
			name: "terminated observation",
			wait: func(_ context.Context, _ windows.Handle, _ windows.Handle, _ time.Duration, requireSignal bool) (bool, error) {
				if requireSignal {
					return false, errInjectedTreeObservation
				}
				return false, nil
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			event, name, closeEvent := testEvent(t)
			defer closeEvent()
			pidPath := filepath.Join(t.TempDir(), "descendant.pid")
			job, port, process := startHelperJob(t, "exit", pidPath, name, "")
			defer closeStoppedJob(t, job, port, process)
			if event, err := windows.WaitForSingleObject(event, 10_000); err != nil || event != windows.WAIT_OBJECT_0 {
				t.Fatalf("wait for helper: event=%d error=%v", event, err)
			}
			err := joinTree(context.Background(), job, port, process.Process, true, test.wait)
			if !errors.Is(err, errInjectedTreeObservation) {
				t.Fatalf("join tree error = %v", err)
			}
			assertDescendantExited(t, pidPath)
		})
	}
}

func TestTerminateAndJoinClosesJobAfterCaptureAndObservationFailure(t *testing.T) {
	event, name, closeEvent := testEvent(t)
	defer closeEvent()
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	job, port, process := startHelperJob(t, "exit", pidPath, name, "")
	defer closeStoppedJob(t, job, port, process)
	if event, err := windows.WaitForSingleObject(event, 10_000); err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("wait for helper: event=%d error=%v", event, err)
	}
	err := terminateAndJoin(
		context.Background(),
		job,
		port,
		process.Process,
		time.Now().Add(joinTimeout),
		errInjectedTreeObservation,
		nil,
		errors.New("injected Cargo process capture failure"),
		func(context.Context, windows.Handle, windows.Handle, time.Duration, bool) (bool, error) {
			return false, errInjectedTreeObservation
		},
		func(windows.Handle) ([]windows.Handle, error) {
			return nil, errors.New("injected Cargo process capture failure")
		},
	)
	if !errors.Is(err, errInjectedTreeObservation) {
		t.Fatalf("terminate and join error = %v", err)
	}
	assertDescendantExited(t, pidPath)
}

func TestWaitJobEmptyHonoursCancellation(t *testing.T) {
	event, name, closeEvent := testEvent(t)
	defer closeEvent()
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	job, port, process := startHelperJob(t, "wait", pidPath, name, "")
	defer closeStartedJob(t, job, port, process)
	if event, err := windows.WaitForSingleObject(event, 10_000); err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("wait for helper: event=%d error=%v", event, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := waitJobEmpty(ctx, job.handle, port, joinTimeout, false)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled observation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled observation did not return promptly")
	}
}

func TestBuildHonoursContextAfterStop(t *testing.T) {
	ctx := newAfterStopContext()
	err := testBuild(t, ctx, "success", "", "", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("after-stop cancellation error = %v", err)
	}
}

func TestValidateRequest(t *testing.T) {
	directory := t.TempDir()
	valid := Request{Arguments: []string{"build"}, Directory: directory, Environment: []string{"PATH=C:\\bin"}}
	if err := validateRequest(valid); err != nil {
		t.Fatalf("valid request error = %v", err)
	}
	for _, request := range []Request{
		{Directory: directory},
		{Arguments: []string{"build"}, Directory: "relative"},
		{Arguments: []string{"build\x00"}, Directory: directory},
		{Arguments: []string{"build"}, Directory: directory, Environment: []string{"PATH=a", "path=b"}},
		{Arguments: []string{"build"}, Directory: directory, Environment: []string{"PATH"}},
	} {
		if err := validateRequest(request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
}

func TestEnvironmentBlock(t *testing.T) {
	block, err := environmentBlock([]string{})
	if err != nil {
		t.Fatalf("empty environment error = %v", err)
	}
	if len(block) != 2 || block[0] != 0 || block[1] != 0 {
		t.Fatalf("empty environment block = %v", block)
	}
	block, err = environmentBlock([]string{"PATH=C:\\bin", "RUSTUP_HOME=C:\\rustup"})
	if err != nil || len(block) < 3 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("non-empty environment block = %v, %v", block, err)
	}
	if err := validateRequest(Request{
		Arguments: []string{"build"}, Directory: t.TempDir(),
		Environment: []string{"=C:=C:\\first", "=c:=C:\\second"},
	}); err == nil {
		t.Fatal("duplicate drive environment key accepted")
	}
}

func TestBuildJoinsCancellationCallbackBeforeClose(t *testing.T) {
	started, startedName, closeStarted := testEvent(t)
	defer closeStarted()
	release, releaseName, closeRelease := testEvent(t)
	defer closeRelease()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- testBuild(t, ctx, "race", "", startedName, releaseName)
	}()
	if event, err := windows.WaitForSingleObject(started, 10_000); err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("wait for helper: event=%d error=%v", event, err)
	}
	cancel()
	if err := windows.SetEvent(release); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("completion cancellation error = %v", err)
	}
}

func TestBuildCancelsBeforeJobAssignment(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, cancelDeadline := context.WithTimeout(parent, 5*time.Second)
	defer cancelDeadline()
	var pid uint32
	err := buildWithStarter(
		ctx,
		helperRequest(t, "success", "", "", ""),
		os.Args[0],
		func(executable string, request Request) (windows.ProcessInformation, error) {
			process, err := startSuspended(executable, request)
			if err == nil {
				pid = process.ProcessId
				cancel()
			}
			return process, err
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-assignment cancellation error = %v", err)
	}
	assertProcessExited(t, pid)
}

func TestCargoBuildHelper(t *testing.T) {
	switch os.Getenv(cargoHelperMode) {
	case "":
		return
	case "success":
		return
	case "wait":
		runChildHelper(t, true)
	case "exit":
		runChildHelper(t, false)
	case "race":
		runCompletionRaceHelper(t)
	case "child":
		waitForTermination(t)
	default:
		t.Fatalf("unknown helper mode %q", os.Getenv(cargoHelperMode))
	}
}

func helperRequest(t *testing.T, mode, pidPath, event, release string) Request {
	t.Helper()
	return Request{
		Arguments: []string{"-test.run=^TestCargoBuildHelper$"},
		Directory: t.TempDir(),
		Environment: append(
			helperEnvironment(),
			cargoHelperMode+"="+mode,
			"CELESTIA_TEST_CARGO_PID="+pidPath,
			"CELESTIA_TEST_CARGO_EVENT="+event,
			"CELESTIA_TEST_CARGO_RELEASE="+release,
		),
	}
}

func helperEnvironment() []string {
	values := os.Environ()
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !strings.HasPrefix(value, "CELESTIA_TEST_CARGO_") {
			result = append(result, value)
		}
	}
	return result
}

func testBuild(t *testing.T, ctx context.Context, mode, pidPath, event, release string) error {
	t.Helper()
	ctx, cancel := testDeadline(ctx)
	defer cancel()
	return buildWithExecutable(ctx, helperRequest(t, mode, pidPath, event, release), os.Args[0])
}

func testDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 5*time.Second)
}

func startHelperJob(
	t *testing.T,
	mode, pidPath, event, release string,
) (*jobOwner, windows.Handle, windows.ProcessInformation) {
	t.Helper()
	job, port, err := newJobOwner()
	if err != nil {
		t.Fatalf("create helper job: %v", err)
	}
	process, err := startSuspended(os.Args[0], helperRequest(t, mode, pidPath, event, release))
	if err != nil {
		closeErr := errors.Join(closeHandle("close helper completion port", port), closeHandle("close helper job", job.handle))
		t.Fatalf("start helper: %v", errors.Join(err, closeErr))
	}
	if err := windows.AssignProcessToJobObject(job.handle, process.Process); err != nil {
		err = discardStartedProcess(process, fmt.Errorf("assign helper job: %w", err))
		closeErr := errors.Join(closeHandle("close helper completion port", port), closeHandle("close helper job", job.handle))
		t.Fatalf("assign helper: %v", errors.Join(err, closeErr))
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		err = finishStoppedBuild(context.Background(), job, port, process.Process, fmt.Errorf("resume helper: %w", err))
		closeErr := errors.Join(closeHandle("close helper thread", process.Thread), closeHandle("close helper process", process.Process), closeHandle("close helper completion port", port), closeHandle("close helper job", job.handle))
		t.Fatalf("resume helper: %v", errors.Join(err, closeErr))
	}
	return job, port, process
}

func closeStartedJob(t *testing.T, job *jobOwner, port windows.Handle, process windows.ProcessInformation) {
	t.Helper()
	if err := finishStoppedBuild(context.Background(), job, port, process.Process, nil); err != nil {
		t.Errorf("stop helper job: %v", err)
	}
	closeStoppedJob(t, job, port, process)
}

func closeStoppedJob(t *testing.T, job *jobOwner, port windows.Handle, process windows.ProcessInformation) {
	t.Helper()
	if err := errors.Join(
		closeHandle("close helper thread", process.Thread),
		closeHandle("close helper process", process.Process),
		closeHandle("close helper completion port", port),
		job.close(),
	); err != nil {
		t.Errorf("close helper job: %v", err)
	}
}

var errInjectedTreeObservation = errors.New("injected Cargo process-tree observation failure")

type afterStopContext struct {
	done chan struct{}
	once sync.Once
}

func newAfterStopContext() *afterStopContext {
	return &afterStopContext{done: make(chan struct{})}
}

func (ctx *afterStopContext) Deadline() (time.Time, bool) {
	return time.Now().Add(time.Minute), true
}

func (ctx *afterStopContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *afterStopContext) Err() error {
	select {
	case <-ctx.done:
		return context.Canceled
	default:
		return nil
	}
}

func (*afterStopContext) Value(any) any {
	return nil
}

func (ctx *afterStopContext) AfterFunc(func()) func() bool {
	return func() bool {
		ctx.once.Do(func() {
			close(ctx.done)
		})
		return true
	}
}

func runChildHelper(t *testing.T, block bool) {
	t.Helper()
	pid := startChildHelper(t)
	retainChildPID(t, pid)
	signalChildStart(t)
	if block {
		waitForTermination(t)
	}
}

func startChildHelper(t *testing.T) uint32 {
	t.Helper()
	child := Request{
		Arguments:   []string{"-test.run=^TestCargoBuildHelper$"},
		Directory:   os.TempDir(),
		Environment: append(helperEnvironment(), cargoHelperMode+"=child"),
	}
	path, err := windows.UTF16PtrFromString(os.Args[0])
	if err != nil {
		t.Fatalf("encode child path: %v", err)
	}
	command, err := windows.UTF16PtrFromString(commandLine(os.Args[0], child.Arguments))
	if err != nil {
		t.Fatalf("encode child command: %v", err)
	}
	environment, err := environmentBlock(child.Environment)
	if err != nil {
		t.Fatalf("encode child environment: %v", err)
	}
	directory, err := windows.UTF16PtrFromString(child.Directory)
	if err != nil {
		t.Fatalf("encode child directory: %v", err)
	}
	var process windows.ProcessInformation
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	if err := windows.CreateProcess(
		path,
		command,
		nil,
		nil,
		false,
		windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT,
		&environment[0],
		directory,
		&startup,
		&process,
	); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := process.ProcessId
	if err := windows.CloseHandle(process.Thread); err != nil {
		t.Fatalf("close child thread: %v", err)
	}
	if err := windows.CloseHandle(process.Process); err != nil {
		t.Fatalf("close child process: %v", err)
	}
	return pid
}

func retainChildPID(t *testing.T, pid uint32) {
	t.Helper()
	pidPath := os.Getenv("CELESTIA_TEST_CARGO_PID")
	if err := os.WriteFile(pidPath, []byte(strconv.FormatUint(uint64(pid), 10)), 0o600); err != nil { // #nosec G703 -- test-controlled temporary PID path.
		t.Fatalf("write child identity: %v", err)
	}

}

func signalChildStart(t *testing.T) {
	t.Helper()
	name := os.Getenv("CELESTIA_TEST_CARGO_EVENT")
	if name == "" {
		return
	}
	event, err := openTestEvent(name)
	if err != nil {
		t.Fatalf("open test event: %v", err)
	}
	if err := windows.SetEvent(event); err != nil {
		closeErr := windows.CloseHandle(event)
		t.Fatalf("signal child start: %v", errors.Join(err, closeErr))
	}
	if err := windows.CloseHandle(event); err != nil {
		t.Fatalf("close test event: %v", err)
	}
}

func runCompletionRaceHelper(t *testing.T) {
	t.Helper()
	started, err := openTestEvent(os.Getenv("CELESTIA_TEST_CARGO_EVENT"))
	if err != nil {
		t.Fatalf("open start event: %v", err)
	}
	if err := windows.SetEvent(started); err != nil {
		closeErr := windows.CloseHandle(started)
		t.Fatalf("signal start event: %v", errors.Join(err, closeErr))
	}
	if err := windows.CloseHandle(started); err != nil {
		t.Fatalf("close start event: %v", err)
	}
	release, err := openTestEvent(os.Getenv("CELESTIA_TEST_CARGO_RELEASE"))
	if err != nil {
		t.Fatalf("open release event: %v", err)
	}
	defer func() {
		if err := windows.CloseHandle(release); err != nil {
			t.Errorf("close release event: %v", err)
		}
	}()
	event, err := windows.WaitForSingleObject(release, windows.INFINITE)
	if err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("wait for release event: event=%d error=%v", event, err)
	}
}

func waitForTermination(t *testing.T) {
	t.Helper()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatalf("create blocking event: %v", err)
	}
	if _, err := windows.WaitForSingleObject(event, windows.INFINITE); err != nil {
		closeErr := windows.CloseHandle(event)
		t.Fatalf("wait for termination: %v", errors.Join(err, closeErr))
	}
	t.Fatal("blocking event was unexpectedly signalled")
}

func testEvent(t *testing.T) (windows.Handle, string, func()) {
	t.Helper()
	name := fmt.Sprintf(
		"Local\\CelestiaTestCargo-%d-%d-%d", os.Getpid(), time.Now().UnixNano(), testEventID.Add(1),
	)
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatalf("encode test event: %v", err)
	}
	event, err := windows.CreateEvent(nil, 1, 0, pointer)
	if err != nil {
		t.Fatalf("create test event: %v", err)
	}
	return event, name, func() {
		if err := windows.CloseHandle(event); err != nil {
			t.Errorf("close test event: %v", err)
		}
	}
}

func openTestEvent(name string) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, pointer)
}

func assertDescendantExited(t *testing.T, pidPath string) {
	t.Helper()
	data, err := os.ReadFile(pidPath) // #nosec G304 -- test-controlled temporary PID path.
	if err != nil {
		t.Fatalf("read descendant identity: %v", err)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if err != nil {
		t.Fatalf("parse descendant identity: %v", err)
	}
	assertProcessExited(t, uint32(pid))
}

func assertProcessExited(t *testing.T, pid uint32) {
	t.Helper()
	if pid == 0 {
		t.Fatal("process identity was not retained")
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Fatalf("open descendant: %v", err)
	}
	defer func() {
		if err := windows.CloseHandle(process); err != nil {
			t.Errorf("close descendant: %v", err)
		}
	}()
	event, err := windows.WaitForSingleObject(process, 0)
	if err != nil {
		t.Fatalf("inspect descendant: %v", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		t.Fatalf("process %d survived build return", pid)
	}
}
