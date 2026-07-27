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

package processsupervision

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestContainerRejectsDuplicateProfile(t *testing.T) {
	var identity [8]byte
	if _, err := rand.Read(identity[:]); err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	name := "celestia.test." + hex.EncodeToString(identity[:])
	container, err := createContainer(name)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer closeContainer(t, &container)
	if _, err := createContainer(name); err == nil {
		t.Fatal("duplicate AppContainer profile was accepted")
	}
	if err := container.close(); err != nil {
		t.Fatalf("close container: %v", err)
	}
}

func TestContainerRejectsInvalidNames(t *testing.T) {
	if err := deleteContainer("invalid\x00name"); err == nil {
		t.Fatal("invalid AppContainer name was accepted")
	}
}

func TestContainerFolderRejectsMissingSID(t *testing.T) {
	t.Parallel()

	if _, err := containerFolder(nil); err == nil {
		t.Fatal("containerFolder(nil) error = nil")
	}
}

func TestSupervisorRejectsReparseWorker(t *testing.T) {
	link := filepath.Join(t.TempDir(), "worker.exe")
	if err := os.Symlink(os.Args[0], link); err != nil {
		t.Skipf("create worker symlink: %v", err)
	}
	if _, err := New(link, testNativeLimits()); err == nil {
		t.Fatal("reparse worker was accepted")
	}
}

func TestWorkerPathPolicy(t *testing.T) {
	tests := map[string]struct {
		path string
		want bool
	}{
		"local":    {path: filepath.Join(t.TempDir(), "worker.exe"), want: true},
		"relative": {path: "worker.exe"},
		"UNC":      {path: `\\invalid.example\share\worker.exe`},
		"device":   {path: `\\?\C:\worker.exe`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := validWorkerPath(test.path); actual != test.want {
				t.Fatalf("validWorkerPath(%q) = %t, want %t", test.path, actual, test.want)
			}
		})
	}
}

func TestResolvedWorkerPathPolicy(t *testing.T) {
	tests := map[string]struct {
		path      string
		driveType uint32
		want      bool
	}{
		"local":  {path: `\\?\C:\worker.exe`, driveType: windows.DRIVE_FIXED, want: true},
		"mapped": {path: `\\?\Z:\worker.exe`, driveType: windows.DRIVE_REMOTE},
		"UNC":    {path: `\\?\UNC\server\share\worker.exe`, driveType: windows.DRIVE_REMOTE},
		"device": {path: `\Device\Mup\server\share\worker.exe`, driveType: windows.DRIVE_REMOTE},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := validLocalFinalPath(test.path, test.driveType); actual != test.want {
				t.Fatalf("validLocalFinalPath(%q) = %t, want %t", test.path, actual, test.want)
			}
		})
	}
}

func TestContainerCloseReportsIdentity(t *testing.T) {
	container := appContainer{name: "invalid\x00name"}
	err := container.close()
	if err == nil || !strings.Contains(err.Error(), "name=") {
		t.Fatalf("close error=%v, want identity", err)
	}
}

func TestContainerCloseRetriesSIDRelease(t *testing.T) {
	sid, err := windows.StringToSid("S-1-0-0")
	if err != nil {
		t.Fatalf("create SID: %v", err)
	}
	container := appContainer{
		name:           "test",
		sid:            sid,
		profileDeleted: true,
	}
	releaseErr := errors.New("release SID")
	if err := container.closeWith(
		func(*windows.SID) error { return releaseErr },
		func(string) error { return nil },
	); !errors.Is(err, releaseErr) {
		t.Fatalf("failed release hidden: %v", err)
	}
	if container.sid == nil || container.sidReleased {
		t.Fatal("failed SID release marked complete")
	}
	if err := container.closeWith(
		func(*windows.SID) error { return nil },
		func(string) error { return nil },
	); err != nil {
		t.Fatalf("retry SID release: %v", err)
	}
	if container.sid != nil || !container.sidReleased {
		t.Fatal("successful SID release not retained")
	}
}

func TestSupervisorDetectsWorkerChange(t *testing.T) {
	source := os.Getenv("CELESTIA_TEST_HOSTILE_WORKER")
	worker := filepath.Join(t.TempDir(), "worker.exe")
	copyFile(t, worker, source)
	supervisor, err := New(worker, testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	if err := os.WriteFile(worker, []byte("changed"), 0o600); err != nil {
		t.Fatalf("change worker: %v", err)
	}
	outcome := supervisor.Run(context.Background(), []byte("malformed"))
	if outcome.Status != StartFailed || outcome.Err == nil {
		t.Fatalf("changed worker: status=%s error=%v", outcome.Status, outcome.Err)
	}
}

func TestSupervisorReportsWorkerHashOnLaunchFailure(t *testing.T) {
	content := []byte("not a Windows executable")
	worker := filepath.Join(t.TempDir(), "worker.exe")
	if err := os.WriteFile(worker, content, 0o600); err != nil {
		t.Fatalf("write worker: %v", err)
	}
	supervisor, err := New(worker, testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	outcome := supervisor.Run(context.Background(), []byte("malformed"))
	expected := sha256.Sum256(content)
	if outcome.Status != StartFailed ||
		outcome.WorkerSHA256 != expected ||
		outcome.Err == nil {
		t.Fatalf(
			"status=%s hash=%x error=%v",
			outcome.Status,
			outcome.WorkerSHA256,
			outcome.Err,
		)
	}
}

func TestFailedLaunchPreservesCleanupState(t *testing.T) {
	outcome := failedLaunchOutcome(time.Now(), false, errors.New("cleanup"))
	if outcome.Status != CleanupFailed || outcome.CleanupComplete {
		t.Fatalf(
			"status=%s cleanup=%t",
			outcome.Status,
			outcome.CleanupComplete,
		)
	}
}

func TestStageImageRejectsFailures(t *testing.T) {
	container, err := createContainerName()
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer closeContainer(t, &container)
	if _, _, _, _, err := stageImage(
		container.folder,
		filepath.Join(t.TempDir(), "missing"),
	); err == nil {
		t.Fatal("missing worker was staged")
	}
	image, _, _, complete, err := stageImage(
		container.folder,
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
	)
	if err != nil {
		t.Fatalf("stage worker: %v", err)
	}
	if !complete {
		t.Fatal("successful staging reported incomplete cleanup")
	}
	defer closeFile(t, image)
	if _, _, _, _, err := stageImage(
		container.folder,
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
	); err == nil {
		t.Fatal("staging collision was accepted")
	}
}

func TestNativeHelpersRejectInvalidState(t *testing.T) {
	t.Run("locked path", func(t *testing.T) {
		if _, err := openLocked("invalid\x00path", windows.GENERIC_READ, windows.OPEN_EXISTING); err == nil {
			t.Fatal("invalid path was accepted")
		}
	})
	t.Run("closed hash", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "closed")
		if err != nil {
			t.Fatalf("create file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close file: %v", err)
		}
		if _, err := hashFile(file); err == nil {
			t.Fatal("closed file was hashed")
		}
	})
	t.Run("closed file cleanup", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "closed")
		if err != nil {
			t.Fatalf("create file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close file: %v", err)
		}
		if err := closeFiles(file); err == nil {
			t.Fatal("failed file cleanup was reported complete")
		}
	})
	t.Run("write handle", func(t *testing.T) {
		result := newInputWriter(windows.InvalidHandle).write([]byte("frame"))
		if result.err == nil {
			t.Fatal("invalid write handle was accepted")
		}
	})
}

func TestEnvironmentUsesWindowsDirectory(t *testing.T) {
	const poisoned = `C:\untrusted-system-root`
	t.Setenv("SystemRoot", poisoned)
	block, err := environmentBlock(t.TempDir())
	if err != nil {
		t.Fatalf("build environment: %v", err)
	}
	environment := string(utf16.Decode(block))
	if strings.Contains(environment, poisoned) {
		t.Fatal("parent SystemRoot was propagated")
	}
	systemRoot, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatalf("find Windows directory: %v", err)
	}
	if !strings.Contains(environment, "SystemRoot="+systemRoot) {
		t.Fatalf("system root missing from %q", environment)
	}
}

func TestCloseHandleRetainsFailedHandle(t *testing.T) {
	handle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatalf("close event: %v", err)
	}
	if err := closeHandle(&handle); err == nil {
		t.Fatal("closed handle close succeeded")
	}
	if handle == 0 {
		t.Fatalf("failed handle cleared: %v", handle)
	}
}

func TestNativeWaitRejectsInvalidState(t *testing.T) {
	t.Run("read handle", func(t *testing.T) {
		result := make(chan streamResult, 1)
		overflow := make(chan Status, 1)
		reader := newStreamReader("output", windows.InvalidHandle)
		reader.read(1, OutputOverflow, result, overflow)
		if (<-result).err == nil {
			t.Fatal("invalid read handle was accepted")
		}
	})
	t.Run("cleanup timeout", func(t *testing.T) {
		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			t.Fatalf("create event: %v", err)
		}
		defer closeNativeHandle(t, event)
		job, complete, err := createJob(testNativeLimits())
		if err != nil {
			t.Fatalf("create job: %v", err)
		}
		if !complete {
			t.Fatal("successful job creation reported incomplete cleanup")
		}
		defer closeNativeHandle(t, job)
		if complete, err := waitCleanup(event, job, time.Millisecond); complete || err == nil {
			t.Fatal("unsignalled process did not time out")
		}
	})
	t.Run("job handle", func(t *testing.T) {
		if _, err := jobEmpty(windows.InvalidHandle); err == nil {
			t.Fatal("invalid job handle was accepted")
		}
	})
	t.Run("wait handle", func(t *testing.T) {
		if complete, err := waitCleanup(
			windows.InvalidHandle,
			windows.InvalidHandle,
			time.Millisecond,
		); complete || err == nil {
			t.Fatal("invalid wait handles were accepted")
		}
	})
}

func TestWaitMillisecondsRoundsUp(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    uint32
	}{
		{name: "whole", timeout: time.Millisecond, want: 1},
		{name: "sub-millisecond", timeout: time.Nanosecond, want: 1},
		{name: "fractional", timeout: time.Millisecond + time.Nanosecond, want: 2},
		{name: "clamped", timeout: time.Duration(1<<63 - 1), want: ^uint32(0) - 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := waitMilliseconds(test.timeout); got != test.want {
				t.Fatalf("waitMilliseconds(%s) = %d, want %d", test.timeout, got, test.want)
			}
		})
	}
}

func TestStreamCancelClosesUnwrappedHandle(t *testing.T) {
	handle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	reader := &streamReader{
		name:   "unwrapped",
		handle: handle,
		done:   make(chan struct{}),
	}
	if err := reader.cancel(); err == nil {
		t.Fatal("non-I/O handle cancellation succeeded")
	}
	if err := windows.CloseHandle(handle); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("handle remains open: %v", err)
	}
}

func TestStartupCleanupJoinsWorker(t *testing.T) {
	for _, assigned := range []bool{false, true} {
		t.Run(map[bool]string{false: "unassigned", true: "assigned"}[assigned], func(t *testing.T) {
			supervisor, err := New(
				os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
				testNativeLimits(),
			)
			if err != nil {
				t.Fatalf("new supervisor: %v", err)
			}
			resources, _, err := supervisor.prepareLaunch(
				context.Background(),
				time.Now().Add(testNativeLimits().StartupTimeout),
			)
			if err != nil {
				t.Fatalf("prepare launch: %v", err)
			}
			defer func() {
				if err := resources.close(); err != nil {
					t.Errorf("close resources: %v", err)
				}
			}()
			info, err := startSuspended(
				resources.container,
				resources.imagePath,
				resources.pipes,
			)
			if err != nil {
				t.Fatalf("start suspended: %v", err)
			}
			if assigned {
				if err := windows.AssignProcessToJobObject(
					resources.job,
					info.Process,
				); err != nil {
					t.Fatalf("assign process: %v", err)
				}
			}
			if err := resources.stopStart(info, assigned); err != nil {
				t.Fatalf("stop startup: %v", err)
			}
		})
	}
}

func TestCancelledStartupNeverResumesWorker(t *testing.T) {
	supervisor, err := New(
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
		testNativeLimits(),
	)
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	resources, _, err := supervisor.prepareLaunch(
		context.Background(),
		time.Now().Add(testNativeLimits().StartupTimeout),
	)
	if err != nil {
		t.Fatalf("prepare launch: %v", err)
	}
	defer func() {
		if err := resources.close(); err != nil {
			t.Errorf("close resources: %v", err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	process, complete, err := resources.start(
		ctx,
		time.Now().Add(testNativeLimits().StartupTimeout),
	)
	if process != nil || !complete || !errors.Is(err, context.Canceled) {
		t.Fatalf("process=%v complete=%t error=%v", process, complete, err)
	}
	outcome := failedLaunchOutcome(time.Now(), complete, err)
	if outcome.Status != Cancelled || !outcome.CleanupComplete {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestExpiredLaunchPreparationClosesPipes(t *testing.T) {
	pipes, complete, err := newPipes()
	if err != nil || !complete {
		t.Fatalf("create pipes: complete=%t error=%v", complete, err)
	}
	resources := &launchResources{
		container: appContainer{
			sidReleased:    true,
			profileDeleted: true,
		},
		pipes: pipes,
	}
	prepared, complete, err := finishLaunchPreparation(
		context.Background(),
		resources,
		time.Now().Add(-time.Second),
	)
	if prepared != nil || !complete || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("prepared=%v complete=%t error=%v", prepared, complete, err)
	}
	if resources.pipes != (pipeSet{}) {
		t.Fatalf("pipe handles retained: %#v", resources.pipes)
	}
}

func TestPipeCloseReportsFailure(t *testing.T) {
	handle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatalf("close event: %v", err)
	}
	operationErr := errors.New("injected pipe creation failure")
	pipes, complete, err := failedPipes(pipeSet{stdinRead: handle}, operationErr)
	if complete || !errors.Is(err, operationErr) {
		t.Fatalf("complete=%t error=%v", complete, err)
	}
	if pipes.stdinRead != handle {
		t.Fatalf("failed pipe handle lost: %#v", pipes)
	}
}

func TestJobCloseReportsFailure(t *testing.T) {
	handle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatalf("close event: %v", err)
	}
	operationErr := errors.New("injected job configuration failure")
	job, complete, err := failedJob(handle, operationErr)
	if job != 0 || complete || !errors.Is(err, operationErr) {
		t.Fatalf("job=%v complete=%t error=%v", job, complete, err)
	}
}

func TestProcessCloseReportsThreadFailure(t *testing.T) {
	thread, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("create thread handle: %v", err)
	}
	processHandle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		closeNativeHandle(t, thread)
		t.Fatalf("create process handle: %v", err)
	}
	job, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		closeNativeHandle(t, thread)
		closeNativeHandle(t, processHandle)
		t.Fatalf("create job handle: %v", err)
	}
	image, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		closeNativeHandle(t, thread)
		closeNativeHandle(t, processHandle)
		closeNativeHandle(t, job)
		t.Fatalf("create image: %v", err)
	}
	if err := windows.CloseHandle(thread); err != nil {
		t.Fatalf("close thread handle: %v", err)
	}
	process := launchedProcess{
		info: windows.ProcessInformation{
			Process: processHandle,
			Thread:  thread,
		},
		job:   job,
		image: image,
		container: appContainer{
			sidReleased:    true,
			profileDeleted: true,
		},
	}
	if err := process.close(); err == nil ||
		!strings.Contains(err.Error(), "close worker thread") {
		t.Fatalf("thread cleanup failure hidden: %v", err)
	}
}

func TestAwaitProcessStates(t *testing.T) {
	t.Run("wait error", func(t *testing.T) {
		status, err := awaitProcess(
			context.Background(),
			make(chan time.Time),
			make(chan time.Time),
			func() (bool, error) {
				return false, errors.New("wait")
			},
			make(chan Status),
			make(chan inputResult),
		)
		if status != ExitFailed || err == nil {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		timeout := make(chan time.Time, 1)
		timeout <- time.Now()
		status, err := awaitProcess(
			context.Background(),
			timeout,
			make(chan time.Time),
			func() (bool, error) { return false, nil },
			make(chan Status),
			make(chan inputResult),
		)
		if status != TimedOut || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("ready completion wins at timeout cutoff", func(t *testing.T) {
		timeout := make(chan time.Time, 1)
		timeout <- time.Now()
		status, err := awaitProcess(
			context.Background(),
			timeout,
			make(chan time.Time),
			func() (bool, error) { return true, nil },
			make(chan Status),
			make(chan inputResult),
		)
		if status != Completed || err != nil {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("ready completion wins at cancellation cutoff", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		status, err := awaitProcess(
			ctx,
			make(chan time.Time),
			make(chan time.Time),
			func() (bool, error) { return true, nil },
			make(chan Status),
			make(chan inputResult),
		)
		if status != Completed || err != nil {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		overflow := make(chan Status, 1)
		overflow <- OutputOverflow
		status, err := awaitProcess(
			context.Background(),
			make(chan time.Time),
			make(chan time.Time),
			func() (bool, error) { return false, nil },
			overflow,
			make(chan inputResult),
		)
		if status != OutputOverflow || !errors.Is(err, errStreamLimit) {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
}

func TestAwaitProcessKeepsTimeout(t *testing.T) {
	timeout := make(chan time.Time, 1)
	timeout <- time.Now()
	input := make(chan inputResult, 1)
	input <- inputResult{}
	result := make(chan struct {
		status Status
		err    error
	}, 1)
	go func() {
		status, err := awaitProcess(
			context.Background(),
			timeout,
			make(chan time.Time),
			func() (bool, error) { return false, nil },
			make(chan Status),
			input,
		)
		result <- struct {
			status Status
			err    error
		}{status: status, err: err}
	}()
	select {
	case outcome := <-result:
		if outcome.status != TimedOut ||
			!errors.Is(outcome.err, context.DeadlineExceeded) {
			t.Fatalf("status=%s error=%v", outcome.status, outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout outcome was discarded")
	}
}

func TestExecutionAllowanceStartsAtResume(t *testing.T) {
	started := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	now := started.Add(750 * time.Millisecond)
	if remaining := executionRemaining(started, 2*time.Second, now); remaining != 1250*time.Millisecond {
		t.Fatalf("remaining allowance=%s", remaining)
	}
	if remaining := executionRemaining(started, 2*time.Second, started.Add(3*time.Second)); remaining >= 0 {
		t.Fatalf("expired allowance=%s", remaining)
	}
}

func TestAwaitInputStates(t *testing.T) {
	input := make(chan inputResult, 1)
	input <- inputResult{}
	deadline := time.Now().Add(time.Second)
	if result := awaitInput(nil, input, deadline, deadline); result != (inputResult{}) {
		t.Fatalf("completed input: %+v", result)
	}
	deadline = time.Now().Add(time.Millisecond)
	if result := awaitInput(
		nil,
		make(chan inputResult),
		deadline,
		deadline.Add(100*time.Millisecond),
	); result.cleanupErr == nil {
		t.Fatal("blocked input join did not time out")
	}
}

func TestAwaitInputCancelsBlockedWrite(t *testing.T) {
	read, write := nativePipe(t)
	defer closeNativeHandle(t, read)
	writer := newInputWriter(write)
	result := make(chan inputResult, 1)
	go func() {
		result <- writer.write(make([]byte, 1<<20))
	}()
	deadline := time.Now().Add(time.Millisecond)
	observation := awaitInput(writer, result, deadline, deadline.Add(100*time.Millisecond))
	if observation.cleanupErr == nil ||
		!strings.Contains(observation.cleanupErr.Error(), "join worker input") {
		t.Fatalf("input result=%v, want bounded join error", observation.cleanupErr)
	}
	select {
	case <-writer.done:
	default:
		t.Fatal("input writer remained active")
	}
}

func TestAwaitStreamCancelsBlockedRead(t *testing.T) {
	read, write := nativePipe(t)
	defer closeNativeHandle(t, write)
	result := make(chan streamResult, 1)
	reader := newStreamReader("output", read)
	go reader.read(8, OutputOverflow, result, make(chan Status, 1))
	deadline := time.Now().Add(time.Millisecond)
	observation := awaitStream(reader, result, deadline, deadline.Add(100*time.Millisecond))
	if observation.cleanupErr == nil ||
		!strings.Contains(observation.cleanupErr.Error(), "join worker output") {
		t.Fatalf("stream result=%v, want bounded join error", observation.cleanupErr)
	}
	select {
	case <-reader.done:
	default:
		t.Fatal("stream reader survived bounded join")
	}
	select {
	case value := <-result:
		t.Fatalf("unjoined stream result=%v", value)
	default:
	}
}

func TestStreamResultStates(t *testing.T) {
	status, err, complete := applyStreamResult(
		Completed,
		nil,
		true,
		streamResult{err: errStreamLimit},
		"output",
		OutputOverflow,
	)
	if status != OutputOverflow || !errors.Is(err, errStreamLimit) || !complete {
		t.Fatalf("overflow: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyStreamResult(
		CleanupFailed,
		errors.New("cleanup"),
		false,
		streamResult{err: errors.New("read")},
		"output",
		OutputOverflow,
	)
	if status != CleanupFailed || err == nil || complete {
		t.Fatalf("cleanup precedence: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyStreamResult(
		Completed,
		nil,
		true,
		streamResult{cleanupErr: errors.New("close")},
		"output",
		OutputOverflow,
	)
	if status != CleanupFailed || err == nil || complete {
		t.Fatalf("stream cleanup: status=%s complete=%t error=%v", status, complete, err)
	}
}

func TestStreamResultPreservesPrimaryStatus(t *testing.T) {
	for _, initial := range []Status{
		TimedOut,
		Cancelled,
		OutputOverflow,
		ErrorOverflow,
		ExitFailed,
	} {
		status, err, complete := applyStreamResult(
			initial,
			errors.New("primary"),
			true,
			streamResult{err: errors.New("read")},
			"output",
			OutputOverflow,
		)
		if status != initial || err == nil || !complete {
			t.Fatalf(
				"secondary read error: initial=%s status=%s complete=%t error=%v",
				initial,
				status,
				complete,
				err,
			)
		}
	}
}

func TestReadExitPreservesPrimaryStatus(t *testing.T) {
	for _, test := range []struct {
		initial Status
		want    Status
	}{
		{initial: Completed, want: ExitFailed},
		{initial: TimedOut, want: TimedOut},
		{initial: Cancelled, want: Cancelled},
		{initial: OutputOverflow, want: OutputOverflow},
		{initial: ErrorOverflow, want: ErrorOverflow},
		{initial: CleanupFailed, want: CleanupFailed},
	} {
		status, _, err := readExit(0, test.initial, errors.New("primary"))
		if status != test.want || err == nil {
			t.Fatalf(
				"initial=%s status=%s want=%s error=%v",
				test.initial,
				status,
				test.want,
				err,
			)
		}
	}
}

func TestInputResultStates(t *testing.T) {
	status, err, complete := applyInputResult(
		Completed,
		nil,
		true,
		inputResult{err: errors.New("write")},
	)
	if status != ExitFailed || err == nil || !complete {
		t.Fatalf("input error: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyInputResult(
		Completed,
		nil,
		true,
		inputResult{cleanupErr: errors.New("close")},
	)
	if status != CleanupFailed || err == nil || complete {
		t.Fatalf("input cleanup: status=%s complete=%t error=%v", status, complete, err)
	}
}

func TestReadPipeStates(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		read, write := nativePipe(t)
		closeNativeHandle(t, write)
		result := make(chan streamResult, 1)
		reader := newStreamReader("output", read)
		reader.read(8, OutputOverflow, result, make(chan Status, 1))
		observation := <-result
		if len(observation.data) != 0 || observation.err != nil {
			t.Fatalf("empty pipe: data=%q error=%v", observation.data, observation.err)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		read, write := nativePipe(t)
		file := os.NewFile(uintptr(write), "test-pipe")
		if _, err := file.Write(bytes.Repeat([]byte("x"), 16)); err != nil {
			t.Fatalf("write pipe: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close pipe: %v", err)
		}
		result := make(chan streamResult, 1)
		overflow := make(chan Status, 1)
		reader := newStreamReader("output", read)
		reader.read(8, OutputOverflow, result, overflow)
		if !errors.Is((<-result).err, errStreamLimit) || <-overflow != OutputOverflow {
			t.Fatal("pipe overflow was not reported")
		}
	})
}

func TestStartRejectsInvalidImage(t *testing.T) {
	container, err := createContainerName()
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer closeContainer(t, &container)
	pipes, complete, err := newPipes()
	if err != nil || !complete {
		t.Fatalf("create pipes: complete=%t error=%v", complete, err)
	}
	defer func() {
		if err := pipes.close(); err != nil {
			t.Errorf("close pipes: %v", err)
		}
	}()
	if _, err := startSuspended(container, filepath.Join(container.folder, "missing.exe"), pipes); err == nil {
		t.Fatal("missing image was started")
	}
}

func testNativeLimits() Limits {
	return Limits{
		InputBytes:     65_536,
		OutputBytes:    8192,
		ErrorBytes:     8192,
		MemoryBytes:    67_108_864,
		Processes:      1,
		StartupTimeout: 2 * time.Second,
		Timeout:        500 * time.Millisecond,
		CleanupTimeout: time.Second,
	}
}

func copyFile(t *testing.T, target, source string) {
	t.Helper()
	// #nosec G304,G703 -- both paths are test-controlled fixture locations.
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// #nosec G703 -- the destination is a test-owned temporary directory.
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func closeContainer(t *testing.T, container *appContainer) {
	t.Helper()
	if err := container.close(); err != nil {
		t.Errorf("close container: %v", err)
	}
}

func closeFile(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil {
		t.Errorf("close file: %v", err)
	}
}

func nativePipe(t *testing.T) (windows.Handle, windows.Handle) {
	t.Helper()
	var read windows.Handle
	var write windows.Handle
	if err := windows.CreatePipe(&read, &write, nil, 0); err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	return read, write
}

func closeNativeHandle(t *testing.T, handle windows.Handle) {
	t.Helper()
	if err := windows.CloseHandle(handle); err != nil {
		t.Errorf("close handle: %v", err)
	}
}
