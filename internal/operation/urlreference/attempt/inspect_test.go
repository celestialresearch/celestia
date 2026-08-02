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

func TestInspectRejectsUnexpectedRecord(t *testing.T) {
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
	path := store.finalPath(accepted.Request.AttemptID)
	if err := os.WriteFile(filepath.Join(path, "unexpected.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write unexpected record: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unexpected record inspected: %v", err)
	}
	if err := store.Recover(
		accepted.Request.AttemptID,
		"unexpected record",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unexpected record recovered: %v", err)
	}
}

func TestInspectRequiresCurrentOwnership(t *testing.T) {
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
	marker := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove ownership marker: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unowned publication inspected: %v", err)
	}
}

func TestInspectRequiresPublicationMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
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
	if _, err := store.Inspect(accepted.Request.AttemptID); err == nil {
		t.Fatal("unpublished receipt inspected as durable")
	}
}

func TestInspectRejectsMissingFields(t *testing.T) {
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
	removeJSONField(t, filepath.Join(path, observationFile), "process_status")
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing field accepted: %v", err)
	}
}

func TestInspectRejectsWrongVersion(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		field string
		value any
	}{
		{name: "admitted version", file: admittedFile, field: "version", value: 1},
		{name: "observation version", file: observationFile, field: "version", value: 1},
		{name: "receipt version", file: receiptFile, field: "version", value: 1},
		{name: "publication version", file: publicationFile, field: "version", value: 1},
		{
			name:  "publication attempt",
			file:  publicationFile,
			field: "attempt_id",
			value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			replaceJSONField(t, filepath.Join(path, test.file), test.field, test.value)
			if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid record accepted: %v", err)
			}
		})
	}
}

func TestStoreRejectsMalformedRecords(t *testing.T) {
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
	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "admitted JSON", file: "admitted.json", data: []byte("{")},
		{name: "receipt JSON", file: "receipt.json", data: []byte("{}{}")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(path, test.file)
			original, readErr := readRooted(path, test.file)
			if readErr != nil {
				t.Fatalf("read record: %v", readErr)
			}
			if writeErr := os.WriteFile(target, test.data, 0o600); writeErr != nil {
				t.Fatalf("write malformed record: %v", writeErr)
			}
			if _, inspectErr := store.Inspect(accepted.Request.AttemptID); inspectErr == nil {
				t.Fatal("malformed record was accepted")
			}
			if writeErr := os.WriteFile(target, original, 0o600); writeErr != nil {
				t.Fatalf("restore record: %v", writeErr)
			}
		})
	}
}
