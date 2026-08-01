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
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

func TestObservationEvidenceRejectsContradictions(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	valid := testObservationFor(t, accepted)

	for name, mutate := range map[string]func(*Observation){
		"stdout overflow": func(value *Observation) {
			value.Stdout = bytes.Repeat(
				[]byte{'x'},
				workerprotocol.MaxResponseBytes+1,
			)
		},
		"stderr overflow": func(value *Observation) {
			value.Stderr = bytes.Repeat(
				[]byte{'x'},
				workerprotocol.StderrBytes+1,
			)
		},
		"valid malformed response": func(value *Observation) {
			value.Stdout = []byte("{")
		},
		"rejected valid response": func(value *Observation) {
			value.ProtocolStatus = "rejected"
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := valid
			mutate(&observation)
			if err := validateObservationEvidence(
				admitted,
				observation,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("contradictory evidence accepted: %v", err)
			}
		})
	}

	notRun := valid
	notRun.ProtocolStatus = "not_run"
	if err := validateObservationEvidence(admitted, notRun); err != nil {
		t.Fatalf("not-run protocol evidence rejected: %v", err)
	}
	rejected := valid
	rejected.ProtocolStatus = "rejected"
	rejected.Stdout = []byte("{")
	if err := validateObservationEvidence(admitted, rejected); err != nil {
		t.Fatalf("rejected protocol evidence rejected: %v", err)
	}
}

func TestRetainedVerificationBindings(t *testing.T) {
	output := "output"
	failed := workerprotocol.Response{Status: workerprotocol.Failed}
	if err := validateRetainedVerificationEvidence(
		workerprotocol.Request{},
		failed,
		Observation{},
	); err != nil {
		t.Fatalf("failed response required verification: %v", err)
	}

	completed := workerprotocol.Response{
		Status: workerprotocol.Completed,
		Output: &output,
	}
	valid := Observation{
		VerificationID:   URLVerifierID,
		VerificationVer:  URLVerifierVersion,
		ExpectedOutput:   output,
		VerificationPass: true,
	}
	if err := validateRetainedVerificationEvidence(
		workerprotocol.Request{},
		completed,
		valid,
	); err != nil {
		t.Fatalf("valid retained verification rejected: %v", err)
	}
	valid.ExpectedOutput = "different"
	if err := validateRetainedVerificationEvidence(
		workerprotocol.Request{},
		completed,
		valid,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("contradictory retained verification accepted: %v", err)
	}
}

func TestDecodeObservationEvidenceRejectsInvalidAdmission(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	observation := testObservationFor(t, accepted)

	admitted.AdmittedAt = "invalid"
	if _, _, err := decodeObservationEvidence(
		admitted,
		observation,
	); err == nil {
		t.Fatal("invalid admitted timestamp accepted")
	}
	admitted = admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	admitted.RequestFrame = []byte("{")
	if _, _, err := decodeObservationEvidence(
		admitted,
		observation,
	); err == nil {
		t.Fatal("invalid admitted request accepted")
	}
}

func TestVerificationEvidenceRejectsInvalidTransformation(t *testing.T) {
	response := workerprotocol.Response{Status: workerprotocol.Failed}
	if err := validateVerificationEvidence(
		workerprotocol.Request{},
		response,
		Observation{},
	); err != nil {
		t.Fatalf("failed response required verification: %v", err)
	}

	output := "output"
	response = workerprotocol.Response{
		Status: workerprotocol.Completed,
		Output: &output,
	}
	request := workerprotocol.Request{Mode: "invalid"}
	if err := validateVerificationEvidence(
		request,
		response,
		Observation{},
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid transformation accepted: %v", err)
	}
}

func TestFailureTransitionHelpers(t *testing.T) {
	base := Observation{
		ProcessStatus:  "completed",
		ProcessError:   "error",
		ProtocolStatus: "not_run",
		TerminalStatus: "failed",
	}
	withVerification := base
	withVerification.VerificationID = "unexpected"
	if validFailedObservation(withVerification) {
		t.Fatal("failed observation retained verification")
	}
	if validCleanupImpairedFailure(Observation{}) {
		t.Fatal("cleanup-impaired failure without process error accepted")
	}
	if validCleanupImpairedFailure(Observation{
		ProcessStatus:  "completed",
		ProcessError:   "error",
		ProtocolStatus: "valid",
	}) {
		t.Fatal("cleanup-impaired failure with protocol result accepted")
	}
	if validCleanupImpairedFailure(Observation{
		ProcessStatus:  "timed_out",
		ProcessError:   "error",
		ProtocolStatus: "not_run",
	}) {
		t.Fatal("unsupported cleanup-impaired failure accepted")
	}

	for _, record := range []Observation{
		{ProtocolStatus: "valid", ExitCode: 2, CleanupComplete: true},
		{ProtocolStatus: "rejected", ExitCode: 0, CleanupComplete: true},
		{ProtocolStatus: "rejected", ExitCode: 2, CleanupComplete: true},
		{ProtocolStatus: "rejected", ExitCode: 3, CleanupComplete: true},
	} {
		if !validCompletedFailure(record) {
			t.Fatalf("completed failure rejected: %+v", record)
		}
	}
	if validCompletedFailure(Observation{
		ProtocolStatus:  "not_run",
		CleanupComplete: true,
	}) {
		t.Fatal("completed failure without protocol outcome accepted")
	}
	if validExitFailure(Observation{}) {
		t.Fatal("exit failure without process error accepted")
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
