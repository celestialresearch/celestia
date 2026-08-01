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
	"time"
)

func TestInspectRetainsReleaseFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	path := store.finalPath(accepted.Request.AttemptID)
	if err := os.Remove(filepath.Join(path, publicationFile)); err != nil {
		t.Fatalf("remove publication marker: %v", err)
	}
	owner, err := store.acquireAttemptLock(accepted.Request.AttemptID, false)
	if err != nil {
		t.Fatalf("acquire inspection lock: %v", err)
	}
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
		activeAttemptLocks.Delete(owner.key)
	})
	records, err := store.inspectWithLock(
		accepted.Request.AttemptID,
		func(string, bool) (*attemptLock, error) {
			if err := publishMarker(path, accepted.Request.AttemptID); err != nil {
				return nil, err
			}
			return owner, nil
		},
	)
	if !errors.Is(err, ErrRelease) ||
		!reflect.DeepEqual(records, Records{}) {
		t.Fatalf("records=%+v error=%v", records, err)
	}
	if err := errors.Join(
		unlockAttemptFile(owner.file),
		owner.file.Close(),
	); err != nil {
		t.Fatalf("release injected owner: %v", err)
	}
	released = true
	activeAttemptLocks.Delete(owner.key)
}

func TestInspectRejectsPublicationBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, string)
	}{
		{
			name: "attempt identity",
			mutate: func(t *testing.T, path, _ string) {
				t.Helper()
				var publication Publication
				recordPath := filepath.Join(path, publicationFile)
				readJSONFile(t, recordPath, &publication)
				accepted, _ := testAccepted(t)
				publication.AttemptID = accepted.Request.AttemptID
				writeJSONFile(t, recordPath, publication)
			},
		},
		{
			name: "receipt hash",
			mutate: func(t *testing.T, path, _ string) {
				t.Helper()
				var publication Publication
				recordPath := filepath.Join(path, publicationFile)
				readJSONFile(t, recordPath, &publication)
				publication.ReceiptHash = strings.Repeat("0", 64)
				writeJSONFile(t, recordPath, publication)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, attemptID, path := publishedAttempt(t)
			test.mutate(t, path, attemptID)
			if _, err := store.Inspect(attemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Inspect() error = %v, want %v", err, ErrCorrupt)
			}
		})
	}
}

func TestReadBundleRejectsReceiptBindings(t *testing.T) {
	tests := []struct {
		name  string
		field func(*Receipt)
	}{
		{
			name: "admitted hash",
			field: func(receipt *Receipt) {
				receipt.AdmittedHash = strings.Repeat("0", 64)
			},
		},
		{
			name: "terminal hash",
			field: func(receipt *Receipt) {
				receipt.TerminalHash = strings.Repeat("0", 64)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, attemptID, path := publishedAttempt(t)
			recordPath := filepath.Join(path, receiptFile)
			var receipt Receipt
			readJSONFile(t, recordPath, &receipt)
			test.field(&receipt)
			writeJSONFile(t, recordPath, receipt)
			if _, err := readBundle(path, attemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("readBundle() error = %v, want %v", err, ErrCorrupt)
			}
		})
	}
}

func TestReadBundleRejectsContradictoryVerification(t *testing.T) {
	_, attemptID, path := publishedAttempt(t)
	observationPath := filepath.Join(path, observationFile)
	var observation Observation
	readJSONFile(t, observationPath, &observation)
	observation.ExpectedOutput = "hxxps://contradiction[.]test/"
	writeJSONFile(t, observationPath, observation)

	terminalHash, err := fileHash(path, observationFile)
	if err != nil {
		t.Fatalf("hash observation: %v", err)
	}
	receiptPath := filepath.Join(path, receiptFile)
	var receipt Receipt
	readJSONFile(t, receiptPath, &receipt)
	receipt.TerminalHash = terminalHash
	writeJSONFile(t, receiptPath, receipt)

	if _, err := readBundle(path, attemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("readBundle() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestValidateBundleFilesRejectsWrongRecordKind(t *testing.T) {
	path := t.TempDir()
	for _, name := range []string{admittedFile, observationFile, receiptFile} {
		if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.Remove(filepath.Join(path, receiptFile)); err != nil {
		t.Fatalf("remove receipt fixture: %v", err)
	}
	if err := os.Mkdir(filepath.Join(path, receiptFile), 0o700); err != nil {
		t.Fatalf("create directory fixture: %v", err)
	}
	if err := validateBundleFiles(path, observationFile, false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("validateBundleFiles() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestInspectRejectsReplacedOwnershipMarker(t *testing.T) {
	store, attemptID, _ := publishedAttempt(t)
	marker := filepath.Join(
		store.root,
		locksDirectory,
		attemptID+ownershipMarkerSuffix,
	)
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove ownership marker: %v", err)
	}
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatalf("replace ownership marker: %v", err)
	}
	if _, err := store.Inspect(attemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("replaced ownership marker accepted: %v", err)
	}
}

func TestReadBundleRejectsReceiptAttemptMismatch(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	other, _ := testAccepted(t)
	root := t.TempDir()
	admitted := Admitted{
		Version:       Version,
		AttemptID:     accepted.Request.AttemptID,
		AdmittedAt:    admittedAt.Format(time.RFC3339Nano),
		OriginalInput: accepted.Request.Input,
		RequestFrame:  accepted.Frame,
	}
	if err := writeRecord(root, admittedFile, admitted); err != nil {
		t.Fatalf("write admitted record: %v", err)
	}
	receipt := Receipt{
		Version:       Version,
		AttemptID:     other.Request.AttemptID,
		TerminalKind:  "observation",
		AdmittedFile:  admittedFile,
		AdmittedHash:  strings.Repeat("0", 64),
		TerminalFile:  observationFile,
		TerminalHash:  strings.Repeat("0", 64),
		TerminalState: "failed",
	}
	if err := writeRecord(root, receiptFile, receipt); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if _, err := readBundle(
		root,
		accepted.Request.AttemptID,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched receipt accepted: %v", err)
	}
}

func TestValidateReceiptRejectsIdentityMismatch(t *testing.T) {
	store, attemptID, _ := publishedAttempt(t)
	records, err := store.Inspect(attemptID)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	accepted, _ := testAccepted(t)
	if err := validateReceipt(
		accepted.Request.AttemptID,
		records.Admitted,
		records.Receipt,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("validateReceipt() error = %v, want %v", err, ErrCorrupt)
	}
}

func TestValidateBundleFilesReportsDirectoryFailures(t *testing.T) {
	t.Parallel()
	path := t.TempDir()
	failure := errors.New("injected directory failure")

	err := validateBundleFilesWith(
		path,
		observationFile,
		true,
		func(*os.Root) (*os.File, error) { return nil, failure },
		func(*os.File) ([]os.DirEntry, error) { return nil, nil },
	)
	if !errors.Is(err, failure) {
		t.Fatalf("open failure = %v", err)
	}

	err = validateBundleFilesWith(
		path,
		observationFile,
		true,
		func(root *os.Root) (*os.File, error) { return root.Open(".") },
		func(*os.File) ([]os.DirEntry, error) { return nil, failure },
	)
	if !errors.Is(err, failure) {
		t.Fatalf("read failure = %v", err)
	}
}

func publishedAttempt(t *testing.T) (*Store, string, string) {
	t.Helper()
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	cleanupAttempt(t, attempt)
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	attemptID := accepted.Request.AttemptID
	return store, attemptID, store.finalPath(attemptID)
}
