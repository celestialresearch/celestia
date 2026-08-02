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
	"strings"
	"testing"
	"time"
)

func TestRecoveryRejectsInvalidShape(t *testing.T) {
	accepted, _ := testAccepted(t)
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := validateRecovery(recovery); err != nil {
		t.Fatalf("valid recovery rejected: %v", err)
	}
	for _, change := range []func(*Recovery){
		func(value *Recovery) { value.Version++ },
		func(value *Recovery) { value.AttemptID = "invalid" },
		func(value *Recovery) { value.TerminalStatus = "failed" },
		func(value *Recovery) { value.Reason = "" },
	} {
		invalid := recovery
		change(&invalid)
		if err := validateRecovery(invalid); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("invalid recovery accepted: %v", err)
		}
	}
}

func TestRecordValidationRejectsMissingRequiredFields(t *testing.T) {
	if err := requireRecordFields([]byte(`{}`), &Recovery{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing record fields accepted: %v", err)
	}
	accepted, admittedAt := testAccepted(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	admitted.RequestFrame = nil
	if err := validateAdmitted(admitted); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing admitted frame accepted: %v", err)
	}
}

func TestRecordValidationRejectsInvalidShapes(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	tests := []struct {
		name   string
		record any
	}{
		{
			name: "admitted",
			record: &Admitted{
				Version:       Version + 1,
				AttemptID:     accepted.Request.AttemptID,
				AdmittedAt:    admittedAt.Format(time.RFC3339Nano),
				OriginalInput: accepted.Request.Input,
				RequestFrame:  accepted.Frame,
			},
		},
		{
			name: "recovery",
			record: &Recovery{
				Version:        Version,
				AttemptID:      accepted.Request.AttemptID,
				TerminalStatus: "verified",
				Reason:         "invalid",
			},
		},
		{
			name: "receipt",
			record: &Receipt{
				Version:      Version,
				AttemptID:    accepted.Request.AttemptID,
				TerminalKind: "unknown",
			},
		},
		{
			name: "publication",
			record: &Publication{
				Version:   Version,
				AttemptID: accepted.Request.AttemptID,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRecord(test.record); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid record accepted: %v", err)
			}
		})
	}
}

func TestRecoveryReasonBounds(t *testing.T) {
	for name, reason := range map[string]string{
		"empty":       "",
		"leading":     " invalid",
		"trailing":    "invalid ",
		"control":     "invalid\nreason",
		"invalid UTF": string([]byte{0xff}),
		"oversized":   strings.Repeat("x", maxRecoveryReasonBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if validRecoveryReason(reason) {
				t.Fatal("invalid recovery reason accepted")
			}
		})
	}
	if !validRecoveryReason("interrupted") {
		t.Fatal("valid recovery reason rejected")
	}
}

func TestAdmittedBindingsRejectCorruption(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	record := admittedRecord(accepted.Request, accepted.Frame, admittedAt)

	invalidFrame := record
	invalidFrame.RequestFrame = []byte("{")
	if err := validateAdmitted(invalidFrame); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid request frame accepted: %v", err)
	}
	mismatchedAttempt := record
	mismatchedAttempt.AttemptID = accepted.Request.RequestNonce
	if err := validateAdmitted(mismatchedAttempt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched attempt accepted: %v", err)
	}
	mismatchedInput := record
	mismatchedInput.OriginalInput = "different"
	if err := validateAdmitted(mismatchedInput); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched input accepted: %v", err)
	}
}

func TestPublicationIdentityBindings(t *testing.T) {
	accepted, _ := testAccepted(t)
	root := t.TempDir()
	publication := Publication{
		Version:     Version,
		AttemptID:   accepted.Request.RequestNonce,
		ReceiptHash: strings.Repeat("a", 64),
	}
	if err := writeRecord(root, publicationFile, publication); err != nil {
		t.Fatal(err)
	}
	if _, err := publicationExists(
		root,
		accepted.Request.AttemptID,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched publication accepted: %v", err)
	}
}

func TestRecordValidators(t *testing.T) {
	for _, status := range []string{
		"failed",
		"cancelled",
		"timed_out",
		"executed_unverified",
		"verified",
		"indeterminate",
	} {
		if !validTerminal(status) {
			t.Fatalf("valid terminal status %q rejected", status)
		}
	}
	if validTerminal("unknown") || validHash("not-a-hash") {
		t.Fatal("invalid record metadata accepted")
	}
	if err := writeRecord(t.TempDir(), "invalid.json", make(chan int)); err == nil {
		t.Fatal("unserialisable record accepted")
	}
}
