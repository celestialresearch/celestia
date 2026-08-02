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

func TestRootCloseFailureReleasesAttemptLock(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	first, err := store.acquireAttemptLock(accepted.Request.AttemptID, true)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	reservation := &lockReservation{key: first.key, keep: true}
	closeErr := errors.New("injected root close failure")
	lock, err := finishLockRootResult(closeErr, reservation, first, nil)
	if lock != nil || !errors.Is(err, closeErr) {
		t.Fatalf("lock=%v error=%v", lock, err)
	}
	second, err := store.acquireAttemptLock(accepted.Request.AttemptID, true)
	if err != nil {
		t.Fatalf("reacquire lock: %v", err)
	}
	if err := second.release(); err != nil {
		t.Fatalf("release second lock: %v", err)
	}
}

func TestStageRejectsLinkedLockFile(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	source := filepath.Join(store.root, "external-lock")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatalf("write linked lock source: %v", err)
	}
	target := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Link(source, target); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked lock accepted: %v", err)
	}
}
