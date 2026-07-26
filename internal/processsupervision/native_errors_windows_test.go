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
	if _, _, _, err := stageImage(container.folder, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing worker was staged")
	}
	image, _, _, err := stageImage(container.folder, os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"))
	if err != nil {
		t.Fatalf("stage worker: %v", err)
	}
	defer closeFile(t, image)
	if _, _, _, err := stageImage(container.folder, os.Getenv("CELESTIA_TEST_HOSTILE_WORKER")); err == nil {
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
	t.Run("environment", func(t *testing.T) {
		t.Setenv("SystemRoot", "")
		if _, err := environmentBlock(t.TempDir()); err == nil {
			t.Fatal("missing SystemRoot was accepted")
		}
	})
	t.Run("write handle", func(t *testing.T) {
		if err := writeFrame(windows.InvalidHandle, []byte("frame")); err == nil {
			t.Fatal("invalid write handle was accepted")
		}
	})
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
		job, err := createJob(testNativeLimits())
		if err != nil {
			t.Fatalf("create job: %v", err)
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
	t.Run("wait bounds", func(t *testing.T) {
		if waitMilliseconds(time.Millisecond) != 1 {
			t.Fatal("ordinary wait conversion failed")
		}
		if waitMilliseconds(time.Duration(1<<63-1)) != ^uint32(0)-1 {
			t.Fatal("large wait was not clamped")
		}
	})
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
	prepared, complete, err := finishLaunchPreparation(resources, time.Now().Add(-time.Second))
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
	if pipes != (pipeSet{}) {
		t.Fatalf("closed pipe handles retained: %#v", pipes)
	}
}

func TestAwaitProcessStates(t *testing.T) {
	t.Run("wait error", func(t *testing.T) {
		waited := make(chan error, 1)
		waited <- errors.New("wait")
		status, err := awaitProcess(
			context.Background(),
			make(chan time.Time),
			waited,
			make(chan Status),
			make(chan error),
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
			make(chan error),
			make(chan Status),
			make(chan error),
		)
		if status != TimedOut || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("ready completion wins at timeout cutoff", func(t *testing.T) {
		timeout := make(chan time.Time, 1)
		timeout <- time.Now()
		waited := make(chan error, 1)
		waited <- nil
		status, err := awaitProcess(
			context.Background(),
			timeout,
			waited,
			make(chan Status),
			make(chan error),
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
			make(chan error),
			overflow,
			make(chan error),
		)
		if status != OutputOverflow || !errors.Is(err, errStreamLimit) {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
}

func TestAwaitProcessKeepsTimeout(t *testing.T) {
	timeout := make(chan time.Time, 1)
	timeout <- time.Now()
	input := make(chan error, 1)
	input <- nil
	result := make(chan struct {
		status Status
		err    error
	}, 1)
	go func() {
		status, err := awaitProcess(
			context.Background(),
			timeout,
			make(chan error),
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
	input := make(chan error, 1)
	input <- nil
	if err := awaitInput(input, time.Second); err != nil {
		t.Fatalf("completed input: %v", err)
	}
	if err := awaitInput(make(chan error), time.Millisecond); err == nil {
		t.Fatal("blocked input join did not time out")
	}
}

func TestAwaitStreamCancelsBlockedRead(t *testing.T) {
	read, write := nativePipe(t)
	defer closeNativeHandle(t, write)
	result := make(chan streamResult, 1)
	reader := newStreamReader("output", read)
	go reader.read(8, OutputOverflow, result, make(chan Status, 1))
	observation := awaitStream(reader, result, time.Now().Add(time.Millisecond))
	if observation.err == nil ||
		!strings.Contains(observation.err.Error(), "join worker output") {
		t.Fatalf("stream result=%v, want bounded join error", observation.err)
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
	status, err := applyStreamResult(
		Completed,
		nil,
		streamResult{err: errStreamLimit},
		"output",
		OutputOverflow,
	)
	if status != OutputOverflow || !errors.Is(err, errStreamLimit) {
		t.Fatalf("overflow: status=%s error=%v", status, err)
	}
	status, err = applyStreamResult(
		CleanupFailed,
		errors.New("cleanup"),
		streamResult{err: errors.New("read")},
		"output",
		OutputOverflow,
	)
	if status != CleanupFailed || err == nil {
		t.Fatalf("cleanup precedence: status=%s error=%v", status, err)
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
