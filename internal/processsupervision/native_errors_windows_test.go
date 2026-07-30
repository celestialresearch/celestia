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
	"unsafe"

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
	if _, err := createContainer("invalid\x00name"); err == nil {
		t.Fatal("invalid AppContainer name was created")
	}
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
		t.Fatalf("create worker symlink: %v", err)
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
	outcome := supervisor.RunBefore(
		context.Background(),
		[]byte("malformed"),
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
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
	outcome := supervisor.RunBefore(
		context.Background(),
		[]byte("malformed"),
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
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
	if outcome.Status != StartFailed || outcome.CleanupComplete {
		t.Fatalf(
			"status=%s cleanup=%t",
			outcome.Status,
			outcome.CleanupComplete,
		)
	}
}

func TestRunRejectsExpiredStartupDeadline(t *testing.T) {
	supervisor, err := New(os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"), testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	outcome := supervisor.RunBefore(context.Background(), []byte("{}"), time.Now().Add(-time.Second))
	if outcome.Status != StartFailed ||
		!outcome.CleanupComplete ||
		!errors.Is(outcome.Err, context.DeadlineExceeded) {
		t.Fatalf("status=%s cleanup=%t error=%v", outcome.Status, outcome.CleanupComplete, outcome.Err)
	}
}

func TestPrepareLaunchCleansCancelledStartup(t *testing.T) {
	supervisor, err := New(os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"), testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resources, complete, err := supervisor.prepareLaunch(
		ctx,
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
	if resources != nil ||
		!complete ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("resources=%v complete=%t error=%v", resources, complete, err)
	}
}

func TestCleanupSucceeded(t *testing.T) {
	if !cleanupSucceeded(true, nil) {
		t.Fatal("successful cleanup rejected")
	}
	if cleanupSucceeded(false, nil) || cleanupSucceeded(true, errors.New("cleanup")) {
		t.Fatal("incomplete cleanup accepted")
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

func TestEnvironmentRejectsInvalidTemporaryDirectory(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(folder, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	if _, err := environmentBlock(folder); err == nil {
		t.Fatal("invalid temporary directory accepted")
	}
}

func TestEnvironmentReportsWindowsDirectoryFailure(t *testing.T) {
	t.Parallel()

	expected := errors.New("directory unavailable")
	_, err := environmentBlockWith(
		t.TempDir(),
		func() (string, error) {
			return "", expected
		},
		os.MkdirAll,
		windows.UTF16FromString,
	)
	if !errors.Is(err, expected) {
		t.Fatalf("environmentBlockWith error = %v, want %v", err, expected)
	}
}

func TestEnvironmentReportsEncodingFailure(t *testing.T) {
	t.Parallel()

	expected := errors.New("encoding unavailable")
	_, err := environmentBlockWith(
		t.TempDir(),
		func() (string, error) {
			return `C:\Windows`, nil
		},
		os.MkdirAll,
		func(string) ([]uint16, error) {
			return nil, expected
		},
	)
	if !errors.Is(err, expected) ||
		!strings.Contains(err.Error(), "encode worker environment") {
		t.Fatalf("environmentBlockWith error = %v, want %v", err, expected)
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
		{name: "zero", timeout: 0, want: 0},
		{name: "negative", timeout: -time.Nanosecond, want: 0},
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

type waitCleanupCase struct {
	name         string
	event        uint32
	waitErr      error
	emptyResults []bool
	emptyErr     error
	times        []time.Time
	wantComplete bool
	wantError    string
	wantSleeps   int
}

func TestWaitCleanupProcessStates(t *testing.T) {
	runWaitCleanupCases(t, []waitCleanupCase{
		{
			name:      "wait failure",
			waitErr:   errors.New("wait"),
			times:     []time.Time{time.Unix(0, 0)},
			wantError: "wait for worker cleanup",
		},
		{
			name:      "process timeout",
			event:     uint32(windows.WAIT_TIMEOUT),
			times:     []time.Time{time.Unix(0, 0)},
			wantError: "worker cleanup deadline",
		},
		{
			name:      "unexpected event",
			event:     42,
			times:     []time.Time{time.Unix(0, 0)},
			wantError: "unexpected worker wait",
		},
	})
}

func TestWaitCleanupTreeStates(t *testing.T) {
	runWaitCleanupCases(t, []waitCleanupCase{
		{
			name:         "empty tree",
			event:        windows.WAIT_OBJECT_0,
			emptyResults: []bool{true},
			times:        []time.Time{time.Unix(0, 0)},
			wantComplete: true,
		},
		{
			name:         "job query failure",
			event:        windows.WAIT_OBJECT_0,
			emptyErr:     errors.New("job"),
			times:        []time.Time{time.Unix(0, 0)},
			wantError:    "job",
			emptyResults: []bool{false},
		},
		{
			name:         "tree becomes empty",
			event:        windows.WAIT_OBJECT_0,
			emptyResults: []bool{false, true},
			times:        []time.Time{time.Unix(0, 0), time.Unix(0, 0)},
			wantComplete: true,
			wantSleeps:   1,
		},
		{
			name:         "tree deadline",
			event:        windows.WAIT_OBJECT_0,
			emptyResults: []bool{false},
			times:        []time.Time{time.Unix(0, 0), time.Unix(1, 0)},
			wantError:    "process tree cleanup deadline",
		},
	})
}

func runWaitCleanupCases(t *testing.T, tests []waitCleanupCase) {
	t.Helper()
	process := windows.Handle(7)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timeIndex := 0
			now := func() time.Time {
				index := min(timeIndex, len(test.times)-1)
				timeIndex++
				return test.times[index]
			}
			emptyIndex := 0
			empty := func() (bool, error) {
				index := min(emptyIndex, len(test.emptyResults)-1)
				emptyIndex++
				return test.emptyResults[index], test.emptyErr
			}
			sleeps := 0
			complete, err := waitCleanupWith(
				process,
				time.Second,
				func(handle windows.Handle, timeout uint32) (uint32, error) {
					if handle != process || timeout != 1000 {
						t.Fatalf("handle=%d timeout=%d", handle, timeout)
					}
					return test.event, test.waitErr
				},
				empty,
				now,
				func(time.Duration) { sleeps++ },
			)
			if complete != test.wantComplete || sleeps != test.wantSleeps {
				t.Fatalf("complete=%t sleeps=%d", complete, sleeps)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("error=%v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v, want %q", err, test.wantError)
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

func TestStreamAndInputCancellationReportCloseFailures(t *testing.T) {
	t.Run("wrapped input", func(t *testing.T) {
		file := closedTemporaryFile(t)
		writer := &inputWriter{file: file, done: make(chan struct{})}
		if err := writer.cancel(); err == nil {
			t.Fatal("closed input file was reported closed")
		}
	})
	t.Run("unwrapped input", func(t *testing.T) {
		handle := closedEvent(t)
		writer := &inputWriter{handle: handle, done: make(chan struct{})}
		if err := writer.cancel(); err == nil {
			t.Fatal("closed input handle was reported closed")
		}
	})
	t.Run("wrapped stream", func(t *testing.T) {
		file := closedTemporaryFile(t)
		reader := &streamReader{
			name: "output", file: file, done: make(chan struct{}),
		}
		if err := reader.cancel(); err == nil {
			t.Fatal("closed stream file was reported closed")
		}
	})
	t.Run("unwrapped stream", func(t *testing.T) {
		handle := closedEvent(t)
		reader := &streamReader{
			name: "output", handle: handle, done: make(chan struct{}),
		}
		if err := reader.cancel(); err == nil {
			t.Fatal("closed stream handle was reported closed")
		}
	})
}

func TestStreamAndInputJoinPreserveCancellationFailure(t *testing.T) {
	deadline := time.Now().Add(-time.Second)
	t.Run("input", func(t *testing.T) {
		writer := &inputWriter{
			file: closedTemporaryFile(t), done: make(chan struct{}),
		}
		result := awaitInput(
			writer,
			make(chan inputResult),
			deadline,
			deadline,
		)
		if result.cleanupErr == nil ||
			!strings.Contains(result.cleanupErr.Error(), "cleanup deadline exceeded") {
			t.Fatalf("cleanup failure lost: %v", result.cleanupErr)
		}
	})
	t.Run("stream", func(t *testing.T) {
		reader := &streamReader{
			name: "output", file: closedTemporaryFile(t),
			done: make(chan struct{}),
		}
		result := awaitStream(
			reader,
			make(chan streamResult),
			deadline,
			deadline,
		)
		if result.cleanupErr == nil ||
			!strings.Contains(result.cleanupErr.Error(), "close worker output") {
			t.Fatalf("cleanup failure lost: %v", result.cleanupErr)
		}
	})
}

func closedTemporaryFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatalf("create temporary file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary file: %v", err)
	}
	return file
}

func closedEvent(t *testing.T) windows.Handle {
	t.Helper()
	handle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	closeNativeHandle(t, handle)
	return handle
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

func TestNativeStructureLayouts(t *testing.T) {
	t.Parallel()
	var capabilities securityCapabilities
	if size := unsafe.Sizeof(capabilities); size != 24 {
		t.Fatalf("security capabilities size = %d, want 24", size)
	}
	if offset := unsafe.Offsetof(capabilities.appContainerSID); offset != 0 {
		t.Fatalf("AppContainer SID offset = %d, want 0", offset)
	}
	var accounting jobAccounting
	if size := unsafe.Sizeof(accounting); size != 48 {
		t.Fatalf("job accounting size = %d, want 48", size)
	}
	if offset := unsafe.Offsetof(accounting.activeProcesses); offset != 40 {
		t.Fatalf("active process offset = %d, want 40", offset)
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

func TestProcessCloseReportsResourceFailures(t *testing.T) {
	t.Run("thread", func(t *testing.T) {
		process := testLaunchedProcess(t)
		closeNativeHandle(t, process.info.Thread)
		assertProcessCloseError(t, &process, "close worker thread")
	})
	t.Run("process", func(t *testing.T) {
		process := testLaunchedProcess(t)
		closeNativeHandle(t, process.info.Process)
		assertProcessCloseError(t, &process, "close worker process")
	})
	t.Run("job", func(t *testing.T) {
		process := testLaunchedProcess(t)
		closeNativeHandle(t, process.job)
		assertProcessCloseError(t, &process, "close worker job")
	})
	t.Run("image", func(t *testing.T) {
		process := testLaunchedProcess(t)
		if err := process.image.Close(); err != nil {
			t.Fatalf("close image: %v", err)
		}
		assertProcessCloseError(t, &process, "close worker image")
	})
	t.Run("container", func(t *testing.T) {
		process := testLaunchedProcess(t)
		process.container = appContainer{
			name:        "invalid\x00profile",
			sidReleased: true,
		}
		assertProcessCloseError(t, &process, "delete AppContainer profile")
	})
}

func testLaunchedProcess(t *testing.T) launchedProcess {
	t.Helper()
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
	return launchedProcess{
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
}

func assertProcessCloseError(
	t *testing.T,
	process *launchedProcess,
	message string,
) {
	t.Helper()
	if err := process.close(); err == nil ||
		!strings.Contains(err.Error(), message) {
		t.Fatalf("%s failure hidden: %v", message, err)
	}
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
