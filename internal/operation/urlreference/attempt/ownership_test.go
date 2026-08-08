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

func TestStageCreatesOwnershipMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() {
		cleanupAttempt(t, attempt)
	})
	present, err := store.hasOwnershipMarker(accepted.Request.AttemptID)
	if err != nil || !present {
		t.Fatalf("ownership marker: present=%t error=%v", present, err)
	}
	if _, err := store.createOwnershipMarkerState(accepted.Request.AttemptID); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate ownership marker: %v", err)
	}
	markerPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.WriteFile(markerPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt ownership marker: %v", err)
	}
	if _, err := store.hasOwnershipMarker(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-empty ownership marker accepted: %v", err)
	}
}

func TestOwnershipMarkerRejectsDirectory(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	present, err := store.hasOwnershipMarker(accepted.Request.AttemptID)
	if err != nil || present {
		t.Fatalf("missing marker: present=%t error=%v", present, err)
	}
	path := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create marker directory: %v", err)
	}
	if _, err := store.hasOwnershipMarker(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("marker directory accepted: %v", err)
	}
}
