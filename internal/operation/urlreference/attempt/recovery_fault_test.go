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
	"reflect"
	"strings"
	"testing"
)

func TestRecoverablePathReportsPublicationConfirmationFailure(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	failure := errors.New("injected publication confirmation failure")
	_, _, err := store.recoverablePathWith(
		accepted.Request.AttemptID,
		func(string) (bool, error) { return true, nil },
		func(string) error { return failure },
	)
	if !errors.Is(err, failure) {
		t.Fatalf("recoverablePathWith() error = %v", err)
	}
}

func TestRecoverReportsPostLockPathFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected post-lock path failure")
	calls := 0
	released := false
	store := &Store{root: `C:\evidence`}
	err := store.recoverWith(
		strings.Repeat("a", 43),
		"interrupted",
		recoveryOperations{
			recoverable: func(string) (string, bool, error) {
				calls++
				if calls == 1 {
					return "pending", false, nil
				}
				return "", false, failure
			},
			acquire: func(string, bool) (*attemptLock, error) {
				return &attemptLock{}, nil
			},
			marker: func(string) (bool, error) {
				t.Fatal("marker checked after path failure")
				return false, nil
			},
			remove: func(string) error { return nil },
			release: func(*attemptLock) error {
				released = true
				return nil
			},
			owned: func(string, string, *attemptLock) error {
				t.Fatal("owned recovery started after path failure")
				return nil
			},
		},
	)
	if !errors.Is(err, failure) || !released || calls != 2 {
		t.Fatalf("error = %v, released = %t, calls = %d", err, released, calls)
	}
}

func TestRecoverOwnedReportsPathFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected owned path failure")
	store := &Store{root: `C:\evidence`}
	err := store.recoverOwnedStateWith(
		strings.Repeat("a", 43),
		"interrupted",
		ownedRecoveryOperations{
			recoverable: func(string) (string, bool, error) {
				return "", false, failure
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("recoverOwnedStateWith() error = %v", err)
	}
}

func TestRecoverOwnedReportsPublicationFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected directory publication failure")
	store := &Store{root: `C:\evidence`}
	err := store.recoverOwnedStateWith(
		strings.Repeat("a", 43),
		"interrupted",
		ownedRecoveryOperations{
			recoverable: func(string) (string, bool, error) {
				return `C:\evidence\pending\attempt`, false, nil
			},
			repair:    func(string) error { return nil },
			published: func(string, string) (bool, error) { return false, nil },
			recover:   func(string, string) error { return nil },
			terminal:  func(string, string, string) error { return nil },
			publish: func(string, string, string) (string, error) {
				return "", failure
			},
			remove: func(string) error { return nil },
			marker: func(string, string) error { return nil },
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("recoverOwnedStateWith() error = %v", err)
	}
}

func TestEnsureTerminalReportsRecordFailures(t *testing.T) {
	t.Parallel()
	accepted, _ := testAccepted(t)
	failure := errors.New("injected terminal record failure")
	receiptCalled := false
	err := ensureTerminalWith(
		"unused",
		accepted.Request.AttemptID,
		"interrupted",
		func(string, string) error { return os.ErrNotExist },
		func(string, string, any) error { return failure },
		func(string, string, string, string, string) error {
			receiptCalled = true
			return nil
		},
	)
	if !errors.Is(err, failure) || receiptCalled {
		t.Fatalf("error=%v receipt-called=%t", err, receiptCalled)
	}
}

func TestRecoverPublishedReportsConfirmationFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected confirmation failure")
	err := recoverPublishedWith(
		"unused",
		"attempt",
		func(string, string) (Records, error) { return Records{}, nil },
		func(string) error { return failure },
	)
	if !errors.Is(err, failure) {
		t.Fatalf("recoverPublishedWith() error = %v", err)
	}
}

func TestRecoverRetriesPendingCleanup(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	blocker := filepath.Join(store.pendingPath(accepted.Request.AttemptID), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write cleanup blocker: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err == nil {
		t.Fatal("recovery ignored pending cleanup failure")
	}
	if _, err := os.Stat(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("terminal bundle was not retained: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err == nil {
		t.Fatal("repeated recovery ignored pending cleanup failure")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatalf("remove cleanup blocker: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err != nil {
		t.Fatalf("retry recovery: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect recovered attempt: %v", err)
	}
	if records.Recovery == nil || records.Receipt.TerminalState != "indeterminate" {
		t.Fatalf("recovery evidence = %+v", records)
	}
}

func TestRecoverRejectsCorruptInterruptedRecord(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	temporary := filepath.Join(attempt.path, "."+receiptFile+"."+strings.Repeat("a", 32))
	if err := os.Mkdir(temporary, 0o700); err != nil {
		t.Fatalf("create corrupt temporary: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt temporary returned %v", err)
	}
}

func TestRecoverRejectsMissingAttemptLock(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove attempt lock: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestRecoverRejectsCorruptOwnershipMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	markerPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.Remove(markerPath); err != nil {
		t.Fatalf("remove ownership marker: %v", err)
	}
	if err := os.Mkdir(markerPath, 0o700); err != nil {
		t.Fatalf("replace ownership marker: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestRecoverRejectsCorruptPublication(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(attempt.path, publicationFile),
		[]byte("{"),
		0o600,
	); err != nil {
		t.Fatalf("write corrupt publication: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt publication returned %v", err)
	}
}

func TestLoadTerminalRejectsObservationIdentityMismatch(t *testing.T) {
	_, attemptID, path := publishedAttempt(t)
	var receipt Receipt
	readJSONFile(t, filepath.Join(path, receiptFile), &receipt)
	var observation Observation
	recordPath := filepath.Join(path, observationFile)
	readJSONFile(t, recordPath, &observation)
	accepted, _ := testAccepted(t)
	observation.AttemptID = accepted.Request.AttemptID
	writeJSONFile(t, recordPath, observation)

	records := Records{Receipt: receipt}
	if err := loadTerminal(path, &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loadTerminal(%s) error = %v, want %v", attemptID, err, ErrCorrupt)
	}
}

func TestLoadTerminalRejectsRecoveryIdentityMismatch(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	attemptID := accepted.Request.AttemptID
	if err := store.Recover(attemptID, "interrupted fixture"); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	path := store.finalPath(attemptID)
	var receipt Receipt
	readJSONFile(t, filepath.Join(path, receiptFile), &receipt)
	var recovery Recovery
	recordPath := filepath.Join(path, recoveryFile)
	readJSONFile(t, recordPath, &recovery)
	other, _ := testAccepted(t)
	recovery.AttemptID = other.Request.AttemptID
	writeJSONFile(t, recordPath, recovery)

	records := Records{Receipt: receipt}
	if err := loadTerminal(path, &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loadTerminal() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestMissingAttemptCannotRecover(t *testing.T) {
	store := newTestStore(t)
	attemptID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	before, err := os.ReadDir(filepath.Join(store.root, locksDirectory))
	if err != nil {
		t.Fatalf("read locks before recovery: %v", err)
	}
	if err := store.Recover(attemptID, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing attempt recovered: %v", err)
	}
	after, err := os.ReadDir(filepath.Join(store.root, locksDirectory))
	if err != nil {
		t.Fatalf("read locks after recovery: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("missing recovery changed locks: before=%v after=%v", before, after)
	}
	if _, err := store.Inspect(attemptID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing attempt inspected: %v", err)
	}
}
