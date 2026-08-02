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

func TestPublishCreatesMarker(t *testing.T) {
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
	if _, err := os.Stat(filepath.Join(store.pendingPath(accepted.Request.AttemptID), bundleDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending bundle still exists: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Publication.Version != Version ||
		records.Publication.AttemptID != accepted.Request.AttemptID ||
		records.Publication.ReceiptHash == "" {
		t.Fatalf("publication=%+v", records.Publication)
	}
	receiptHash, err := fileHash(
		store.finalPath(accepted.Request.AttemptID),
		receiptFile,
	)
	if err != nil {
		t.Fatalf("hash receipt: %v", err)
	}
	if records.receiptHash != receiptHash ||
		records.Publication.ReceiptHash != receiptHash {
		t.Fatalf(
			"receipt hashes: retained=%q publication=%q file=%q",
			records.receiptHash,
			records.Publication.ReceiptHash,
			receiptHash,
		)
	}
}

func TestPublishedIdentityCannotRestage(t *testing.T) {
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
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("published identity restaged: %v", err)
	}
}

func TestPublicationRequiresFinalReadBack(t *testing.T) {
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
	path, err := attempt.publishDirectory()
	if err != nil {
		t.Fatalf("publish directory: %v", err)
	}
	if err := os.Remove(filepath.Join(path, observationFile)); err != nil {
		t.Fatalf("remove observation: %v", err)
	}
	if err := publishMarker(path, accepted.Request.AttemptID); err == nil {
		t.Fatal("incomplete final bundle published")
	}
}

func TestPublicationRejectsUnexpectedRecord(t *testing.T) {
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
	path, err := attempt.publishDirectory()
	if err != nil {
		t.Fatalf("publish directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "unexpected.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write unexpected record: %v", err)
	}
	if err := publishMarker(path, accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unexpected record published: %v", err)
	}
}
