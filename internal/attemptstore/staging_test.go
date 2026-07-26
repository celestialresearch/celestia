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

package attemptstore

import (
	"errors"
	"os"
	"testing"
)

func TestStageFailurePreservesAttemptOwnership(t *testing.T) {
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
	)
	if !errors.Is(err, writeErr) {
		t.Fatalf("stage failure: %v", err)
	}
	released = true
	if err := owner.release(); err != nil {
		t.Fatalf("release failed attempt: %v", err)
	}
	if marker, err := store.hasOwnershipMarker(request.AttemptID); err != nil || !marker {
		t.Fatalf("ownership marker lost: present=%t error=%v", marker, err)
	}
	if _, err := os.Lstat(store.pendingPath(request.AttemptID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending attempt retained: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("failed attempt reused: %v", err)
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
		t.Cleanup(func() { _ = os.RemoveAll(pendingPath) })
	}
	if !errors.Is(err, createErr) {
		t.Fatalf("prepare failure: %v", err)
	}
	if pendingPath != store.pendingPath(accepted.Request.AttemptID) || path != "" {
		t.Fatalf("pending=%q bundle=%q", pendingPath, path)
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
