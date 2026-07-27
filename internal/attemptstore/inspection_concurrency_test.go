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
	t.Cleanup(func() { _ = attempt.Close() })
	if err := attempt.publishLocked(
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
	t.Cleanup(func() { _ = attempt.Close() })
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	const readers = 8
	var group sync.WaitGroup
	errors := make(chan error, readers)
	for range readers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := store.Inspect(accepted.Request.AttemptID)
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent inspect: %v", err)
		}
	}
}
