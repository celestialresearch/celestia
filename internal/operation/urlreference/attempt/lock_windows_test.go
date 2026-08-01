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

package attemptstore

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestActiveLockCannotBeReplacedWhileOwnerAlive(t *testing.T) {
	store, accepted, _ := lockProcessFixture(t)
	command := lockHelperCommand(t.Context(), "stage", store.root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	stopped := false
	stopHelper := func() {
		if stopped {
			return
		}
		stopped = true
		if err := stopLockHelper(command); err != nil {
			t.Errorf("stop helper: %v", err)
		}
	}
	defer stopHelper()
	if scanner := bufio.NewScanner(stdout); !scanner.Scan() || scanner.Text() != "staged" {
		t.Fatalf("helper did not stage: %v", scanner.Err())
	}

	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Rename(lockPath, lockPath+".replacement"); err == nil {
		t.Fatal("active lock was replaceable while owner process was alive")
	}
	if err := store.Recover(accepted.Request.AttemptID, "owner still active"); !errors.Is(err, ErrActive) {
		t.Fatalf("active lock was not retained: %v", err)
	}

	stopHelper()
	if err := store.Recover(accepted.Request.AttemptID, "owner process ended"); err != nil {
		t.Fatalf("recover after owner death: %v", err)
	}
}

func TestAttemptLockRejectsSharedDACL(t *testing.T) {
	store, accepted, admittedAt := lockProcessFixture(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	setSharedDACL(t, lockPath)
	if _, err := store.acquireAttemptLock(accepted.Request.AttemptID, false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("shared lock DACL accepted: %v", err)
	}
}

func TestWindowsLockPathsFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := openWindowsLockFile(
		t.TempDir(),
		"invalid\x00.lock",
		windows.GENERIC_READ,
		windows.OPEN_EXISTING,
		nil,
	); err == nil {
		t.Fatal("openWindowsLockFile() accepted an embedded NUL")
	}
	if err := syncAttemptLockDirectory("invalid\x00path"); err == nil {
		t.Fatal("syncAttemptLockDirectory() accepted an embedded NUL")
	}
	if err := syncAttemptLockDirectory(
		filepath.Join(t.TempDir(), "missing"),
	); err == nil {
		t.Fatal("syncAttemptLockDirectory() accepted a missing directory")
	}
}

func TestSecureLockFileReportsClosedHandle(t *testing.T) {
	t.Parallel()

	directory := protectedTestDirectory(t)
	file, err := openAttemptLockFile(nil, directory, "closed.lock", true)
	if err != nil {
		t.Fatalf("create lock fixture: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat lock fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close lock fixture: %v", err)
	}
	if err := secureLockFile(file, info); err == nil {
		t.Fatal("secureLockFile() accepted a closed handle")
	}
}

func TestSecureLockFileRejectsHardLink(t *testing.T) {
	t.Parallel()

	directory := protectedTestDirectory(t)
	file, err := openAttemptLockFile(nil, directory, "linked.lock", true)
	if err != nil {
		t.Fatalf("create lock fixture: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close lock fixture: %v", err)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat lock fixture: %v", err)
	}
	if err := os.Link(file.Name(), filepath.Join(directory, "alias.lock")); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}
	if err := secureLockFile(file, info); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("secureLockFile() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestOpenAttemptLockReportsDescriptorFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("descriptor unavailable")
	_, err := openAttemptLockFileWith(
		t.TempDir(),
		"attempt.lock",
		true,
		func() (*windows.SECURITY_DESCRIPTOR, error) {
			return nil, failure
		},
		openWindowsLockFile,
	)
	if !errors.Is(err, failure) {
		t.Fatalf("openAttemptLockFileWith() error = %v, want %v", err, failure)
	}
}

func TestOpenWindowsLockClosesUnwrappedHandle(t *testing.T) {
	t.Parallel()

	closed := false
	_, err := openWindowsLockFileWith(
		t.TempDir(),
		"attempt.lock",
		windows.GENERIC_READ,
		windows.OPEN_EXISTING,
		nil,
		windows.UTF16PtrFromString,
		func(
			*uint16,
			uint32,
			uint32,
			*windows.SecurityAttributes,
			uint32,
			uint32,
			windows.Handle,
		) (windows.Handle, error) {
			return 9, nil
		},
		func(uintptr, string) *os.File { return nil },
		func(handle windows.Handle) error {
			closed = handle == 9
			return nil
		},
	)
	if err == nil || !closed {
		t.Fatalf("error = %v, closed = %t", err, closed)
	}
}
