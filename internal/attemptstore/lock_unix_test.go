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

//go:build !windows

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"
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
