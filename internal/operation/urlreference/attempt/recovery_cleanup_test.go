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

//go:build windows || (linux && amd64)

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverRemovesPendingParentAfterRename(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := writeOrMatchRecord(attempt.path, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := writeOrMatchReceipt(
		attempt.path,
		accepted.Request.AttemptID,
		"observation",
		observationFile,
		observation.TerminalStatus,
	); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if _, err := publishPendingDirectory(
		attempt.path,
		store.finalPath(accepted.Request.AttemptID),
		store.attemptsPath(),
	); err != nil {
		t.Fatalf("rename bundle: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "pending cleanup interrupted"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if _, err := os.Lstat(store.pendingPath(accepted.Request.AttemptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending parent retained: %v", err)
	}
}

func TestStoreRejectsPendingPathReplacementDuringCleanup(t *testing.T) {
	if err := removePendingDirectory(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("missing pending path: %v", err)
	}
	directory := filepath.Join(t.TempDir(), "pending-directory")
	if err := createEvidenceDirectory(directory); err != nil {
		t.Fatalf("create pending directory: %v", err)
	}
	if err := removePendingDirectory(directory); err != nil {
		t.Fatalf("remove pending directory: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pending")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write pending replacement: %v", err)
	}
	if err := removePendingDirectory(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("pending file replacement accepted: %v", err)
	}
}

func TestRemovePendingSyncsParent(t *testing.T) {
	t.Parallel()

	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	failure := errors.New("injected pending sync failure")
	removed := false
	err = removePendingDirectoryWith(
		filepath.Join("parent", "pending"),
		pendingRemovalOperations{
			lstat:  func(string) (os.FileInfo, error) { return info, nil },
			linked: func(string, os.FileInfo) bool { return false },
			secure: func(string) error { return nil },
			remove: func(string) error {
				removed = true
				return nil
			},
			sync: func(path string) error {
				if !removed {
					t.Fatal("sync called before removal")
				}
				if path != "parent" {
					t.Fatalf("sync path = %q, want parent", path)
				}
				return failure
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("removePendingDirectoryWith() error = %v", err)
	}
}
