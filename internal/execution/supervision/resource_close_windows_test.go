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

package supervision

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"

	"strings"
	"testing"
)

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
	job, complete, err := failedJobWith(handle, operationErr, windows.CloseHandle)
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
