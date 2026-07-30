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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStageFailureBeforeCommitCanRetry(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	request, err := validateAccepted(accepted, admittedAt)
	if err != nil {
		t.Fatalf("validate accepted request: %v", err)
	}
	owner, err := store.acquireAttemptLock(request.AttemptID, true)
	if err != nil {
		t.Fatalf("acquire attempt lock: %v", err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			if err := owner.release(); err != nil {
				t.Errorf("release failed attempt: %v", err)
			}
		}
	})
	writeErr := errors.New("injected admitted-record failure")
	_, err = store.stageOwned(
		accepted,
		request,
		admittedAt,
		owner,
		func(string, string, any) error { return writeErr },
		store.createOwnershipMarkerState,
	)
	if !errors.Is(err, writeErr) {
		t.Fatalf("stage failure: %v", err)
	}
	released = true
	if err := owner.release(); err != nil {
		t.Fatalf("release failed attempt: %v", err)
	}
	if marker, err := store.hasOwnershipMarker(request.AttemptID); err != nil || marker {
		t.Fatalf("ownership marker present=%t error=%v", marker, err)
	}
	if _, err := os.Lstat(store.pendingPath(request.AttemptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending attempt retained: %v", err)
	}
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("retry Stage() error = %v", err)
	}
	cleanupAttempt(t, attempt)
}

func TestStagePreservesCommittedStateAfterMarkerError(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	request, err := validateAccepted(accepted, admittedAt)
	if err != nil {
		t.Fatalf("validate accepted request: %v", err)
	}
	owner, err := store.acquireAttemptLock(request.AttemptID, true)
	if err != nil {
		t.Fatalf("acquire attempt lock: %v", err)
	}
	injected := errors.New("injected post-creation marker failure")
	_, stageErr := store.stageOwned(
		accepted, request, admittedAt, owner, writeRecord,
		func(attemptID string) (bool, error) {
			created, markerErr := store.createOwnershipMarkerState(attemptID)
			if markerErr != nil {
				return created, markerErr
			}
			return created, injected
		},
	)
	if !errors.Is(stageErr, injected) {
		t.Fatalf("stageOwned() error = %v", stageErr)
	}
	if err := owner.release(); err != nil {
		t.Fatalf("release attempt lock: %v", err)
	}
	if _, err := os.Lstat(store.pendingPath(request.AttemptID)); err != nil {
		t.Fatalf("committed pending attempt lost: %v", err)
	}
	if err := store.Recover(request.AttemptID, "marker finalisation failed"); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := store.Inspect(request.AttemptID); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestStageRequiresCommittedOwnershipMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	request, err := validateAccepted(accepted, admittedAt)
	if err != nil {
		t.Fatalf("validate accepted request: %v", err)
	}
	_, err = store.stageOwned(
		accepted, request, admittedAt, nil, writeRecord,
		func(string) (bool, error) { return false, nil },
	)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("stage error = %v, want %v", err, ErrCorrupt)
	}
	if _, err := os.Lstat(store.pendingPath(request.AttemptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted attempt retained: %v", err)
	}
}

func TestStageOwnedRejectsInvalidRoot(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request, err := validateAccepted(accepted, admittedAt)
	if err != nil {
		t.Fatalf("validate accepted request: %v", err)
	}
	store := &Store{root: "invalid\x00root"}
	if _, err := store.stageOwned(
		accepted,
		request,
		admittedAt,
		nil,
		writeRecord,
		func(string) (bool, error) { return true, nil },
	); err == nil {
		t.Fatal("invalid staging root accepted")
	}
}

func TestStageRejectsMarkerOnlyAttempt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	if err := store.createOwnershipMarker(attemptID); err != nil {
		t.Fatalf("create ownership marker: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("marker-only attempt reused: %v", err)
	}
	if marker, err := store.hasOwnershipMarker(attemptID); err != nil || !marker {
		t.Fatalf("ownership marker lost: present=%t error=%v", marker, err)
	}
}

func TestRecoverRejectsPublishedAttemptWithoutMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	marker := filepath.Join(
		store.root, locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID, "missing marker",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := os.Lstat(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("published attempt changed: %v", err)
	}
}

func TestAttemptPreparationReturnsAcquiredPendingPath(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	createCalls := 0
	createErr := errors.New("injected bundle-directory failure")
	pendingPath, path, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		func(path string) error {
			createCalls++
			if createCalls == 1 {
				return createEvidenceDirectory(path)
			}
			return createErr
		},
	)
	if pendingPath != "" {
		t.Cleanup(func() {
			if err := os.RemoveAll(pendingPath); err != nil {
				t.Errorf("remove pending fixture: %v", err)
			}
		})
	}
	if !errors.Is(err, createErr) {
		t.Fatalf("prepare failure: %v", err)
	}
	if pendingPath != store.pendingPath(accepted.Request.AttemptID) || path != "" {
		t.Fatalf("pending=%q bundle=%q", pendingPath, path)
	}
}

func TestAttemptPreparationClassifiesCreationFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	injected := errors.New("injected creation failure")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "existing pending attempt", err: os.ErrExist, want: ErrDuplicate},
		{name: "creation failure", err: injected, want: injected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := store.prepareAttemptDirectories(
				accepted.Request.AttemptID,
				func(string) error { return test.err },
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("prepare error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRollbackWithoutStagedPathDoesNothing(t *testing.T) {
	store := newTestStore(t)
	called := false
	if err := store.rollbackStage("", func(string) error {
		called = true
		return errors.New("unexpected rollback")
	}); err != nil {
		t.Fatalf("rollback error = %v", err)
	}
	if called {
		t.Fatal("rollback called without a staged path")
	}
}

func TestStageRollbackKeepsMarkerWhenPendingSurvives(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	if err := store.createOwnershipMarker(attemptID); err != nil {
		t.Fatalf("create ownership marker: %v", err)
	}
	removeErr := errors.New("injected pending rollback failure")
	err := store.rollbackStage(
		store.pendingPath(attemptID),
		func(string) error { return removeErr },
	)
	if !errors.Is(err, removeErr) {
		t.Fatalf("rollback failure: %v", err)
	}
	if marker, err := store.hasOwnershipMarker(attemptID); err != nil || !marker {
		t.Fatalf("ownership marker lost: present=%t error=%v", marker, err)
	}
}

func TestStagedAttemptRollbackSyncsPendingRoot(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	pendingPath := store.pendingPath(accepted.Request.AttemptID)
	if err := createEvidenceDirectory(pendingPath); err != nil {
		t.Fatalf("create pending attempt: %v", err)
	}
	syncErr := errors.New("injected pending-root sync failure")
	var synced string
	err := removeStagedAttemptWith(pendingPath, func(path string) error {
		synced = path
		return syncErr
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("remove staged attempt error = %v, want %v", err, syncErr)
	}
	if synced != store.pendingRoot() {
		t.Fatalf("synced path = %q, want %q", synced, store.pendingRoot())
	}
	if _, err := os.Lstat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending attempt retained: %v", err)
	}
}

func TestStagedAttemptRollbackRejectsInvalidPath(t *testing.T) {
	called := false
	err := removeStagedAttemptWith("invalid\x00path", func(string) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("invalid rollback error=%v sync-called=%t", err, called)
	}
}

func TestDuplicateCheckRejectsInvalidRoot(t *testing.T) {
	accepted, _ := testAccepted(t)
	store := &Store{root: "invalid\x00root"}
	if err := store.rejectDuplicateAttempt(
		accepted.Request.AttemptID,
	); err == nil {
		t.Fatal("invalid duplicate-check root accepted")
	}
}

func TestDuplicateCheckRejectsExistingAttempt(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID

	for _, path := range []string{
		store.finalPath(attemptID),
		store.pendingPath(attemptID),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create attempt path: %v", err)
		}
		if err := store.rejectDuplicateAttempt(attemptID); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("reject duplicate attempt: %v", err)
		}
		if err := os.RemoveAll(path); err != nil {
			t.Fatalf("remove attempt path: %v", err)
		}
	}
}
