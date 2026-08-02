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
	"celestia.research/celestia/internal/execution/supervision"

	"errors"

	"golang.org/x/sys/windows"

	"strconv"
	"strings"
	"testing"
	"time"
)

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
