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
	"strings"
	"sync"
	"testing"
)

func TestInspectReadsOwnedPublication(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if _, err := attempt.publishLockedMeasured(
		testObservationFor(t, accepted),
	); err != nil {
		t.Fatalf("publish while retaining ownership: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect immutable publication: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("close attempt: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect released publication: %v", err)
	}
}

func TestInspectAllowsConcurrentReaders(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	const readers = 8
	var group sync.WaitGroup
	errors := make(chan error, readers)
	for range readers {
		group.Go(func() {
			_, err := store.Inspect(accepted.Request.AttemptID)
			errors <- err
		})
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent inspect: %v", err)
		}
	}
}

func TestInspectLocksBeforeClassifyingPublication(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() {
		cleanupAttempt(t, attempt)
	})
	if _, err := attempt.publishLockedMeasured(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish while retaining ownership: %v", err)
	}
	path, err := store.attemptPath(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("attempt path: %v", err)
	}
	temporary := filepath.Join(
		path,
		"."+publicationFile+"."+strings.Repeat("a", 32),
	)
	if err := os.Link(filepath.Join(path, publicationFile), temporary); err != nil {
		t.Fatalf("link in-flight publication: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove publication link: %v", err)
		}
	})
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrActive) {
		t.Fatalf("in-flight publication returned %v", err)
	}
}

func TestInspectRejectsMissingCurrentLock(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	lock := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Remove(lock); err != nil {
		t.Fatalf("remove lock: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing current lock returned %v", err)
	}
}
