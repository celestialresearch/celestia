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
	"testing"
)

func TestPublishResultDistinguishesReleaseFailure(t *testing.T) {
	publicationErr := errors.New("publication")
	releaseErr := errors.New("release")
	if err := publishResult(nil, nil); err != nil {
		t.Fatalf("successful publication failed: %v", err)
	}
	if err := publishResult(publicationErr, nil); !errors.Is(err, publicationErr) ||
		!errors.Is(err, ErrPublication) {
		t.Fatalf("publication failure lost: %v", err)
	}
	if err := publishResult(nil, releaseErr); !errors.Is(err, ErrRelease) {
		t.Fatalf("release failure not classified: %v", err)
	}
	err := publishResult(publicationErr, releaseErr)
	if !errors.Is(err, publicationErr) ||
		!errors.Is(err, ErrPublication) ||
		!errors.Is(err, ErrRelease) {
		t.Fatalf("combined failure lost: %v", err)
	}
}

func TestPublishClassifiesReleaseAfterPublication(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	owner := attempt.owner
	owner.once.Do(func() {
		owner.releaseErr = errors.New("injected release failure")
	})
	released := false
	t.Cleanup(func() {
		if released {
			return
		}
		if err := errors.Join(
			unlockAttemptFile(owner.file),
			owner.file.Close(),
		); err != nil {
			t.Errorf("clean up injected owner: %v", err)
		}
	})
	err = attempt.Publish(testObservationFor(t, accepted))
	if !errors.Is(err, ErrRelease) {
		t.Fatalf("release failure not classified: %v", err)
	}
	if err := unlockAttemptFile(owner.file); err != nil {
		t.Fatalf("release injected owner: %v", err)
	}
	if err := owner.file.Close(); err != nil {
		t.Fatalf("close injected owner: %v", err)
	}
	released = true
	activeAttemptLocks.Delete(owner.key)
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("published attempt not inspectable: %v", err)
	}
}

func TestNilAttemptClose(t *testing.T) {
	var attempt *Attempt
	if err := attempt.Close(); err != nil {
		t.Fatalf("close nil attempt: %v", err)
	}
}

func TestAttemptCloseIsIdempotent(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestStorePublishesAndInspects(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := attempt.Publish(observation); err != nil {
		t.Fatalf("publish: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil ||
		records.Recovery != nil ||
		records.Admitted.OriginalInput != accepted.Request.Input ||
		string(records.Admitted.RequestFrame) != string(accepted.Frame) ||
		records.Observation.TerminalStatus != "verified" {
		t.Fatalf("records=%+v", records)
	}
}
