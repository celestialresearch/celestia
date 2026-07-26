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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package attemptstore

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStageRejectsPermissiveLockFile(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	// #nosec G306 -- permissive mode is the rejected security fixture.
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("permissive lock accepted: %v", err)
	}
}

func TestRecoverRejectsMissingLock(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove lock path: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("close attempt: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"missing lock",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing lock recovered: %v", err)
	}
	if err := store.MigrateV0(
		accepted.Request.AttemptID,
		"operator quiesced legacy attempt",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("current attempt migrated: %v", err)
	}
}

func TestRecoverRejectsReplacedLockDirectory(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"directory": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatalf("create replacement directory: %v", err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			t.Helper()
			target := t.TempDir()
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("create replacement symlink: %v", err)
			}
		},
	}
	for name, replace := range tests {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			accepted, admittedAt := testAccepted(t)
			attempt, err := store.Stage(accepted, admittedAt)
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			defer func() {
				_ = attempt.Close()
			}()
			lockDirectory := filepath.Join(store.root, locksDirectory)
			if err := os.Rename(lockDirectory, lockDirectory+".original"); err != nil {
				t.Fatalf("move lock directory: %v", err)
			}
			replace(t, lockDirectory)
			if err := store.Recover(
				accepted.Request.AttemptID,
				"replaced lock directory",
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("replaced lock directory accepted: %v", err)
			}
		})
	}
}

func TestStageDoesNotRecreateMissingActiveLock(t *testing.T) {
	store, accepted, admittedAt := lockProcessFixture(t)
	command := lockHelperCommand(t.Context(), "stage", store.root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "staged" {
		t.Fatalf("helper did not stage: %v", scanner.Err())
	}
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("helper exited before test: %v", err)
	}
	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove active lock path: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate stage result: %v", err)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("duplicate stage recreated lock: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"missing active lock",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing active lock recovered: %v", err)
	}
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("helper exited during test: %v", err)
	}
}
