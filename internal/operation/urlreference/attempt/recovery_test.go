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

func TestRecoverPublishesAfterReceiptFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := writeOrMatchRecord(attempt.path, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "receipt write failed"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil ||
		records.Recovery != nil ||
		records.Observation.TerminalStatus != "verified" {
		t.Fatalf("records=%+v", records)
	}
}

func TestRecoverResumesRecoveryReceipt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted before receipt",
	}
	if err := writeOrMatchRecord(attempt.path, recoveryFile, recovery); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, recovery.Reason); err != nil {
		t.Fatalf("resume recovery: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Recovery == nil ||
		records.Observation != nil ||
		records.Recovery.Reason != recovery.Reason {
		t.Fatalf("records=%+v", records)
	}
}

func TestRecoverPublishesAfterMarkerFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := writeOrMatchRecord(attempt.path, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := writeOrMatchReceipt(
		attempt.path,
		accepted.Request.AttemptID,
		"observation",
		observationFile,
		observation.TerminalStatus,
	); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if _, err := attempt.publishDirectory(); err != nil {
		t.Fatalf("publish directory: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "marker write failed"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect: %v", err)
	}
}

func TestExistingTerminalRejectsContradiction(t *testing.T) {
	root := t.TempDir()
	accepted, _ := testAccepted(t)
	observation := testObservationFor(t, accepted)
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := writeRecord(root, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := writeRecord(root, recoveryFile, recovery); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	if err := publishExistingTerminal(root, accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("contradictory terminals accepted: %v", err)
	}
}

func TestExistingTerminalRejectsIdentityMismatch(t *testing.T) {
	accepted, _ := testAccepted(t)
	other, _ := testAccepted(t)
	tests := []struct {
		name  string
		file  string
		value any
	}{
		{
			name:  "observation",
			file:  observationFile,
			value: testObservationFor(t, other),
		},
		{
			name: "recovery",
			file: recoveryFile,
			value: Recovery{
				Version:        Version,
				AttemptID:      other.Request.AttemptID,
				TerminalStatus: "indeterminate",
				Reason:         "interrupted",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := writeRecord(root, test.file, test.value); err != nil {
				t.Fatalf("write terminal: %v", err)
			}
			if err := publishExistingTerminal(root, accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("mismatched terminal accepted: %v", err)
			}
		})
	}
}

func TestExistingTerminalRejectsMalformedSibling(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := testObservationFor(t, accepted)
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	tests := []struct {
		name       string
		validFile  string
		validValue any
		badFile    string
	}{
		{
			name:       "observation with malformed recovery",
			validFile:  observationFile,
			validValue: observation,
			badFile:    recoveryFile,
		},
		{
			name:       "recovery with malformed observation",
			validFile:  recoveryFile,
			validValue: recovery,
			badFile:    observationFile,
		},
		{
			name:    "malformed observation only",
			badFile: observationFile,
		},
		{
			name:    "malformed recovery only",
			badFile: recoveryFile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.validFile != "" {
				if err := writeRecord(root, test.validFile, test.validValue); err != nil {
					t.Fatalf("write valid terminal: %v", err)
				}
			}
			if err := os.WriteFile(
				filepath.Join(root, test.badFile),
				[]byte("{"),
				0o600,
			); err != nil {
				t.Fatalf("write malformed terminal: %v", err)
			}
			if err := publishExistingTerminal(
				root,
				accepted.Request.AttemptID,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("malformed terminal accepted: %v", err)
			}
		})
	}
}

func TestRecoverablePathRejectsInvalidIdentity(t *testing.T) {
	store := &Store{}
	if _, _, err := store.recoverablePath("invalid"); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("invalid recovery identity accepted: %v", err)
	}
}

func TestRecoverablePathPropagatesFilesystemFailure(t *testing.T) {
	store := &Store{root: "invalid\x00root"}
	attemptID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, err := store.recoverablePath(attemptID); err == nil {
		t.Fatal("invalid recovery path accepted")
	}
}

func TestRecoverablePathPropagatesPendingFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	target := t.TempDir()
	if err := os.Symlink(
		target,
		store.pendingPath(accepted.Request.AttemptID),
	); err != nil {
		t.Fatalf("link pending-path fixture: %v", err)
	}
	if _, _, err := store.recoverablePath(
		accepted.Request.AttemptID,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked pending path returned %v", err)
	}
}

func TestEnsureTerminalRejectsAdmittedIdentityMismatch(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	root := t.TempDir()
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	if err := writeRecord(root, admittedFile, admitted); err != nil {
		t.Fatal(err)
	}
	store := &Store{}
	if err := store.ensureTerminal(
		root,
		accepted.Request.RequestNonce,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched recovery identity accepted: %v", err)
	}
}

func TestEnsureTerminalRejectsCorruptExistingTerminal(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	root := protectedTestDirectory(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	if err := writeRecord(root, admittedFile, admitted); err != nil {
		t.Fatalf("write admitted record: %v", err)
	}
	if err := writeRecord(root, observationFile, map[string]bool{"invalid": true}); err != nil {
		t.Fatalf("write corrupt terminal: %v", err)
	}
	store := &Store{}
	if err := store.ensureTerminal(
		root,
		accepted.Request.AttemptID,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt terminal accepted: %v", err)
	}
}

func TestStoreRejectsUnknownRecoveryIdentity(t *testing.T) {
	store := newTestStore(t)
	if err := store.Recover("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown recovery identity returned %v", err)
	}
}

func TestStoreRecoversPendingAttempt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Recovery == nil ||
		records.Observation != nil ||
		records.Receipt.TerminalState != "indeterminate" {
		t.Fatalf("records=%+v", records)
	}
	if err := store.Recover(accepted.Request.AttemptID, "again"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("repeat recovery: %v", err)
	}
}

func TestRecoveryRejectsInvalidReceiptState(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	receiptPath := filepath.Join(store.pendingPath(accepted.Request.AttemptID), bundleDirectory, receiptFile)
	if err := os.Mkdir(receiptPath, 0o700); err != nil {
		t.Fatalf("create receipt directory: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err == nil {
		t.Fatal("invalid receipt state accepted recovery")
	}
}

func TestStoreRejectsIncompleteAttempts(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if _, err := store.Inspect(accepted.Request.AttemptID); err == nil {
		t.Fatal("pending attempt inspected as terminal")
	}
	if err := store.Recover(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"missing",
	); err == nil {
		t.Fatal("missing attempt recovered")
	}
}

func TestTerminalLoaderRejectsMismatches(t *testing.T) {
	root := t.TempDir()
	observation := testObservation("attempt")
	if err := writeRecord(root, "observation.json", observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	records := Records{Receipt: Receipt{
		AttemptID:     "other",
		TerminalKind:  "observation",
		TerminalFile:  "observation.json",
		TerminalState: observation.TerminalStatus,
	}}
	if err := loadTerminal(root, &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("observation mismatch: %v", err)
	}

	recovery := Recovery{
		Version:        Version,
		AttemptID:      "attempt",
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := writeRecord(root, "recovery.json", recovery); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	records = Records{Receipt: Receipt{
		AttemptID:     "other",
		TerminalKind:  "recovery",
		TerminalFile:  "recovery.json",
		TerminalState: recovery.TerminalStatus,
	}}
	if err := loadTerminal(root, &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("recovery mismatch: %v", err)
	}
	records = Records{Receipt: Receipt{
		AttemptID:     "attempt",
		TerminalKind:  "observation",
		TerminalFile:  "missing.json",
		TerminalState: "failed",
	}}
	if err := loadTerminal(root, &records); err == nil {
		t.Fatal("missing terminal accepted")
	}
}

func TestRecoverRejectsActiveAttempt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() {
		cleanupAttempt(t, attempt)
	})
	if err := store.Recover(accepted.Request.AttemptID, "active"); !errors.Is(err, ErrActive) {
		t.Fatalf("active attempt recovered: %v", err)
	}
	other, err := New(store.root)
	if err != nil {
		t.Fatalf("open second store: %v", err)
	}
	if err := other.Recover(accepted.Request.AttemptID, "active"); !errors.Is(err, ErrActive) {
		t.Fatalf("second store recovered active attempt: %v", err)
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
