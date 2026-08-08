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
	"path/filepath"
	"testing"
)

func TestValidateAttemptLockRejectsIncompleteOwner(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	key := filepath.Join(store.root, locksDirectory, attemptID+".lock")
	t.Cleanup(func() {
		activeAttemptLocks.Delete(key)
	})

	activeAttemptLocks.Store(key, struct{}{})
	if err := store.validateAttemptLock(attemptID); !errors.Is(err, ErrActive) {
		t.Fatalf("reserved attempt lock error = %v, want %v", err, ErrActive)
	}

	activeAttemptLocks.Store(key, &attemptLock{})
	if err := store.validateAttemptLock(attemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing owned attempt lock error = %v, want %v", err, ErrCorrupt)
	}
}
