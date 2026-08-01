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
	"strings"
	"testing"
)

func TestNewStoreReportsConstructionFailures(t *testing.T) {
	failure := errors.New("injected store construction failure")
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	base := func() storeCreationOperations {
		return storeCreationOperations{
			prepareRoot:        func(string) (string, error) { return `C:\evidence`, nil },
			prepareDirectories: func(string) error { return nil },
			createLock:         func(string) (bool, error) { return false, nil },
			validateDirectories: func(string) error {
				return nil
			},
			syncLocks: func(string) error { return nil },
			lstat: func(string) (os.FileInfo, error) {
				return info, nil
			},
		}
	}
	tests := []struct {
		name    string
		replace func(*storeCreationOperations)
	}{
		{
			name: "prepare root",
			replace: func(operations *storeCreationOperations) {
				operations.prepareRoot = func(string) (string, error) {
					return "", failure
				}
			},
		},
		{
			name: "prepare directories",
			replace: func(operations *storeCreationOperations) {
				operations.prepareDirectories = func(string) error { return failure }
			},
		},
		{
			name: "create lock directory",
			replace: func(operations *storeCreationOperations) {
				operations.createLock = func(string) (bool, error) {
					return false, failure
				}
			},
		},
		{
			name: "validate directories",
			replace: func(operations *storeCreationOperations) {
				operations.validateDirectories = func(string) error { return failure }
			},
		},
		{
			name: "sync lock directory",
			replace: func(operations *storeCreationOperations) {
				operations.createLock = func(string) (bool, error) { return true, nil }
				operations.syncLocks = func(string) error { return failure }
			},
		},
		{
			name: "inspect lock directory",
			replace: func(operations *storeCreationOperations) {
				operations.lstat = func(string) (os.FileInfo, error) {
					return nil, failure
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := base()
			test.replace(&operations)
			if _, err := newStoreWith("root", operations); !errors.Is(err, failure) {
				t.Fatalf("newStoreWith() error = %v", err)
			}
		})
	}
}

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

func TestValidateAcceptedRejectsMalformedFrame(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	accepted.Frame = []byte("{")
	if _, err := validateAccepted(accepted, admittedAt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateAccepted() error = %v, want %v", err, ErrInvalid)
	}
}

func TestReleaseErrorPreservesCause(t *testing.T) {
	cause := errors.New("release fixture")
	err := releaseError(cause)
	if !errors.Is(err, ErrRelease) || !errors.Is(err, cause) {
		t.Fatalf("releaseError() error = %v", err)
	}
}

func TestPublishedAttemptDirectoryIsStable(t *testing.T) {
	attempt := &Attempt{path: `C:\evidence\attempt`}
	path, err := attempt.publishDirectory()
	if err != nil || path != attempt.path {
		t.Fatalf("publishDirectory() path = %q, error = %v", path, err)
	}
}

func TestAttemptPreparationRejectsPublishedIdentity(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	if err := createEvidenceDirectory(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("create published fixture: %v", err)
	}
	if _, _, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		createEvidenceDirectory,
	); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("prepareAttemptDirectories() error = %v, want %v", err, ErrDuplicate)
	}
}

func TestAttemptPreparationRejectsInvalidRoot(t *testing.T) {
	accepted, _ := testAccepted(t)
	store := &Store{root: "invalid\x00root"}
	if _, _, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		createEvidenceDirectory,
	); err == nil {
		t.Fatal("invalid attempt root accepted")
	}
}

func TestPublishPendingDirectoryRejectsExistingTarget(t *testing.T) {
	parent := protectedTestDirectory(t)
	source := filepath.Join(parent, "source")
	target := filepath.Join(parent, "target")
	for _, path := range []string{source, target} {
		if err := createEvidenceDirectory(path); err != nil {
			t.Fatalf("create %s: %v", filepath.Base(path), err)
		}
	}
	if _, err := publishPendingDirectory(source, target, parent); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("publishPendingDirectory() error = %v, want %v", err, ErrDuplicate)
	}
}

func TestRemovePendingDirectoryRejectsInvalidState(t *testing.T) {
	t.Run("non-directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pending")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write pending fixture: %v", err)
		}
		if err := removePendingDirectory(path); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("removePendingDirectory() error = %v, want %v", err, ErrCorrupt)
		}
	})

	t.Run("non-empty directory", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "owned")
		if err := createEvidenceDirectory(parent); err != nil {
			t.Fatalf("create protected parent: %v", err)
		}
		path := filepath.Join(parent, "pending")
		if err := createEvidenceDirectory(path); err != nil {
			t.Fatalf("create pending directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "record"), nil, 0o600); err != nil {
			t.Fatalf("write pending record: %v", err)
		}
		if err := removePendingDirectory(path); err == nil {
			t.Fatal("removePendingDirectory() removed a non-empty directory")
		}
	})
}

func TestReceiptCreationRequiresBothRecords(t *testing.T) {
	path := protectedTestDirectory(t)
	accepted, _ := testAccepted(t)
	if err := writeOrMatchReceipt(
		path,
		accepted.Request.AttemptID,
		"observation",
		observationFile,
		"verified",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writeOrMatchReceipt() error = %v, want missing record", err)
	}
}

func TestPublicationRequiresReceipt(t *testing.T) {
	path := protectedTestDirectory(t)
	accepted, _ := testAccepted(t)
	if err := publishMarker(path, accepted.Request.AttemptID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publishMarker() error = %v, want missing receipt", err)
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

func TestPublishDirectoryRetainsCleanupFailure(t *testing.T) {
	t.Parallel()

	accepted, _ := testAccepted(t)
	failure := errors.New("injected pending cleanup failure")
	attempt := &Attempt{
		store:       &Store{root: `C:\evidence`},
		path:        `C:\evidence\pending\attempt`,
		pendingPath: `C:\evidence\pending`,
		admitted:    Admitted{AttemptID: accepted.Request.AttemptID},
	}
	path, err := attempt.publishDirectoryWith(pendingPublicationOperations{
		publish: func(string, string, string) (string, error) {
			return `C:\evidence\attempts\attempt`, nil
		},
		remove: func(string) error { return failure },
	})
	if path != "" || !errors.Is(err, failure) ||
		attempt.pendingPath != "" {
		t.Fatalf(
			"path = %q, error = %v, pending = %q",
			path,
			err,
			attempt.pendingPath,
		)
	}
}

func TestRemovePendingReportsSecurityFailure(t *testing.T) {
	t.Parallel()

	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	failure := errors.New("injected pending security failure")
	err = removePendingDirectoryWith(
		"unused",
		pendingRemovalOperations{
			lstat:  func(string) (os.FileInfo, error) { return info, nil },
			linked: func(string, os.FileInfo) bool { return false },
			secure: func(string) error { return failure },
			remove: func(string) error {
				t.Fatal("remove called after security failure")
				return nil
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("removePendingDirectoryWith() error = %v", err)
	}
}

func TestPublishMarkerReportsWriteFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected marker write failure")
	err := publishMarkerWith(
		"unused",
		"attempt",
		markerPublicationOperations{
			read: func(string, string) (Records, error) {
				return Records{
					Receipt:     Receipt{TerminalFile: observationFile},
					receiptHash: strings.Repeat("a", 64),
				}, nil
			},
			validate: func(string, string, bool) error { return nil },
			write: func(string, string, any) error {
				return failure
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("publishMarkerWith() error = %v", err)
	}
}

func TestPublishRejectsConflictingReceipt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	conflict := Receipt{
		Version:       Version,
		AttemptID:     accepted.Request.AttemptID,
		TerminalKind:  "recovery",
		AdmittedFile:  admittedFile,
		AdmittedHash:  strings.Repeat("a", 64),
		TerminalFile:  recoveryFile,
		TerminalHash:  strings.Repeat("b", 64),
		TerminalState: "indeterminate",
	}
	if err := writeRecord(attempt.path, receiptFile, conflict); err != nil {
		t.Fatalf("write conflicting receipt: %v", err)
	}
	err = attempt.Publish(testObservationFor(t, accepted))
	if !errors.Is(err, ErrPublication) || !errors.Is(err, ErrDuplicate) {
		t.Fatalf("conflicting receipt accepted: %v", err)
	}
}

func TestPublishRejectsFinalDirectoryCollision(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := createEvidenceDirectory(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("create final collision: %v", err)
	}
	err = attempt.Publish(testObservationFor(t, accepted))
	if !errors.Is(err, ErrPublication) || !errors.Is(err, ErrDuplicate) {
		t.Fatalf("final collision accepted: %v", err)
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

func TestRemovePendingRejectsInvalidPath(t *testing.T) {
	if err := removePendingDirectory("invalid\x00path"); err == nil {
		t.Fatal("invalid pending path accepted")
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

func protectedTestDirectory(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "owned")
	if err := createEvidenceDirectory(parent); err != nil {
		t.Fatalf("create protected parent: %v", err)
	}
	path := filepath.Join(parent, "records")
	if err := createEvidenceDirectory(path); err != nil {
		t.Fatalf("create protected records: %v", err)
	}
	return path
}
