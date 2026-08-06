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
	"strings"
	"testing"
)

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
