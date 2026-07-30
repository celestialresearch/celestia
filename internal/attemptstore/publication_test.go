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

package attemptstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestReadRecordRejectsNonCanonicalJSON(t *testing.T) {
	root := t.TempDir()
	recovery := Recovery{
		Version:        Version,
		AttemptID:      strings.Repeat("A", 43),
		TerminalStatus: "indeterminate",
		Reason:         "fixture",
	}
	canonical, err := json.Marshal(recovery)
	if err != nil {
		t.Fatalf("encode recovery: %v", err)
	}
	tests := map[string][]byte{
		"leading whitespace": append([]byte(" "), canonical...),
		"duplicate field": append(
			bytes.TrimSuffix(canonical, []byte("}")),
			[]byte(`,"version":1}`)...,
		),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write record: %v", err)
			}
			var actual Recovery
			if err := readRecord(root, filepath.Base(path), &actual); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("non-canonical record accepted: %v", err)
			}
		})
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

func TestReadRootedBoundsEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "large.json"),
		make([]byte, maxRecordBytes+1),
		0o600,
	); err != nil {
		t.Fatalf("write large record: %v", err)
	}
	if _, err := readRooted(root, "large.json"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("large record accepted: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatalf("create directory record: %v", err)
	}
	if _, err := readRooted(root, "directory"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory record accepted: %v", err)
	}
}

func TestObservationRejectsUnknownStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	tests := []struct {
		name   string
		change func(*Observation)
	}{
		{
			name: "process",
			change: func(observation *Observation) {
				observation.ProcessStatus = "unknown"
			},
		},
		{
			name: "protocol",
			change: func(observation *Observation) {
				observation.ProtocolStatus = "unknown"
			},
		},
		{
			name: "duration",
			change: func(observation *Observation) {
				observation.DurationNS = -1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := testObservationFor(t, accepted)
			test.change(&observation)
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid observation accepted: %v", err)
			}
		})
	}
}

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

func TestObservationRejectsContradictoryTerminal(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := testObservationFor(t, accepted)
	observation.ProcessStatus = "exit_failed"
	observation.ProtocolStatus = "not_run"
	observation.VerificationID = ""
	observation.VerificationVer = ""
	observation.ExpectedOutput = ""
	observation.VerificationPass = false
	if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("contradictory verified observation accepted: %v", err)
	}
}

func TestObservationRejectsInvalidTerminalTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := testObservationFor(t, accepted)
	for _, terminal := range []string{"unknown", "cancelled", "timed_out"} {
		t.Run(terminal, func(t *testing.T) {
			observation := base
			observation.TerminalStatus = terminal
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid terminal transition accepted: %v", err)
			}
		})
	}
}

func TestObservationRejectsTimeoutWithoutProcessError(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := observationWithoutVerification(
		testObservationFor(t, accepted),
	)
	observation.ProcessStatus = "timed_out"
	observation.ProcessError = ""
	observation.ProtocolStatus = "not_run"
	observation.TerminalStatus = "timed_out"
	if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("timeout without process error accepted: %v", err)
	}
}

func TestObservationAcceptsContractTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	verified := testObservationFor(t, accepted)
	unverified := verified
	unverified.TerminalStatus = "executed_unverified"
	unverified.VerificationPass = false
	failedResponse := observationWithoutVerification(verified)
	failedResponse.TerminalStatus = "failed"
	failedResponse.ExitCode = 2
	workerFailed := failedResponse
	workerFailed.ProcessStatus = "exit_failed"
	workerFailed.ProcessError = "worker status failed"
	workerFailed.ExitCode = 3
	failedProcess := failedResponse
	failedProcess.ProcessStatus = "exit_failed"
	failedProcess.ProtocolStatus = "not_run"
	failedProcess.ProcessError = "worker failed"
	failedProcess.ExitCode = 0
	cancelled := failedProcess
	cancelled.ProcessStatus = "cancelled"
	cancelled.TerminalStatus = "cancelled"
	timedOut := failedProcess
	timedOut.ProcessStatus = "timed_out"
	timedOut.TerminalStatus = "timed_out"
	deadlineCancelled := timedOut
	deadlineCancelled.ProcessStatus = "cancelled"
	for _, observation := range []Observation{
		verified,
		unverified,
		failedResponse,
		workerFailed,
		failedProcess,
		cancelled,
		timedOut,
		deadlineCancelled,
	} {
		if err := validateObservation(observation); err != nil {
			t.Fatalf("valid transition rejected: %+v: %v", observation, err)
		}
	}
}

func TestObservationAcceptsAndRejectsCleanupFailureTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.TerminalStatus = "failed"
	validCleanupFailure := base
	validCleanupFailure.ProcessStatus = "cleanup_failed"
	validCleanupFailure.ProcessError = "cleanup failed"
	validCleanupFailure.CleanupComplete = false
	validCleanupFailure.ProtocolStatus = "not_run"
	if err := validateObservation(validCleanupFailure); err != nil {
		t.Fatalf("valid cleanup failure rejected: %v", err)
	}
	invalidCleanupFailure := validCleanupFailure
	invalidCleanupFailure.CleanupComplete = true
	if err := validateObservation(invalidCleanupFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cleanup failure with complete cleanup accepted: %v", err)
	}
	validProcessFailure := base
	validProcessFailure.ProcessStatus = "output_overflow"
	validProcessFailure.ProcessError = "output limit"
	validProcessFailure.CleanupComplete = true
	validProcessFailure.ProtocolStatus = "not_run"
	if err := validateObservation(validProcessFailure); err != nil {
		t.Fatalf("valid output failure rejected: %v", err)
	}
	validStartFailure := validProcessFailure
	validStartFailure.ProcessStatus = "start_failed"
	validStartFailure.ProcessError = "start failed"
	validStartFailure.Stdout = nil
	validStartFailure.Stderr = nil
	if err := validateObservation(validStartFailure); err != nil {
		t.Fatalf("valid start failure rejected: %v", err)
	}
	invalidCompletedFailure := validProcessFailure
	invalidCompletedFailure.ProcessStatus = "completed"
	invalidCompletedFailure.ProcessError = "unexpected process error"
	if err := validateObservation(invalidCompletedFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("completed failure with process error accepted: %v", err)
	}
	invalidProcessFailure := validProcessFailure
	invalidProcessFailure.ProcessStatus = "cancelled"
	if err := validateObservation(invalidProcessFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cancelled failed observation accepted: %v", err)
	}
}

func TestObservationPreservesPrimaryOutcomeDuringCleanupFailure(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.ProcessError = "primary and cleanup failure"
	base.ProtocolStatus = "not_run"
	base.CleanupComplete = false
	tests := []struct {
		process  string
		terminal string
	}{
		{process: "timed_out", terminal: "timed_out"},
		{process: "cancelled", terminal: "cancelled"},
		{process: "exit_failed", terminal: "failed"},
		{process: "completed", terminal: "failed"},
		{process: "output_overflow", terminal: "failed"},
		{process: "error_overflow", terminal: "failed"},
		{process: "cleanup_failed", terminal: "failed"},
		{process: "start_failed", terminal: "failed"},
	}
	for _, test := range tests {
		observation := base
		observation.ProcessStatus = test.process
		observation.TerminalStatus = test.terminal
		if test.process == "start_failed" {
			observation.Stdout = nil
			observation.Stderr = nil
		}
		if err := validateObservation(observation); err != nil {
			t.Fatalf("%s with cleanup failure rejected: %v", test.process, err)
		}
	}
}

func TestObservationRejectsInvalidCleanupImpairedStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.ProcessStatus = "start_failed"
	base.ProcessError = "start and cleanup failed"
	base.ProtocolStatus = "not_run"
	base.CleanupComplete = false
	base.TerminalStatus = "failed"
	tests := []struct {
		name   string
		mutate func(*Observation)
	}{
		{
			name: "start exit code",
			mutate: func(observation *Observation) {
				observation.ExitCode = 1
			},
		},
		{
			name: "start output",
			mutate: func(observation *Observation) {
				observation.Stdout = []byte("unexpected")
			},
		},
		{
			name: "unknown process",
			mutate: func(observation *Observation) {
				observation.ProcessStatus = "unknown"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			test.mutate(&observation)
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid cleanup-impaired state accepted: %+v", observation)
			}
		})
	}
}

func TestObservationRejectsStartFailureStreams(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := observationWithoutVerification(testObservationFor(t, accepted))
	observation.ProcessStatus = "start_failed"
	observation.ProcessError = "start failed"
	observation.ExitCode = 0
	observation.ProtocolStatus = "not_run"
	observation.Stdout = []byte("worker did not start")
	for _, terminal := range []string{"failed", "timed_out"} {
		observation.TerminalStatus = terminal
		if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s start failure streams accepted: %+v", terminal, observation)
		}
	}
}

func TestObservationRejectsContradictoryProcessProtocolStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.TerminalStatus = "failed"
	base.ProcessError = "worker failed"
	base.CleanupComplete = true
	tests := []struct {
		name     string
		process  string
		protocol string
		exitCode uint32
	}{
		{name: "start valid", process: "start_failed", protocol: "valid"},
		{name: "start rejected", process: "start_failed", protocol: "rejected"},
		{name: "start exit", process: "start_failed", protocol: "not_run", exitCode: 1},
		{name: "output valid", process: "output_overflow", protocol: "valid", exitCode: 1},
		{name: "output rejected", process: "output_overflow", protocol: "rejected", exitCode: 1},
		{name: "error valid", process: "error_overflow", protocol: "valid", exitCode: 1},
		{name: "exit valid", process: "exit_failed", protocol: "valid", exitCode: 1},
		{name: "exit rejected code", process: "exit_failed", protocol: "valid", exitCode: 2},
		{name: "cancelled failed", process: "cancelled", protocol: "not_run", exitCode: 1},
		{name: "timed out failed", process: "timed_out", protocol: "not_run", exitCode: 1},
		{name: "completed not run", process: "completed", protocol: "not_run"},
		{name: "completed valid zero", process: "completed", protocol: "valid"},
		{name: "completed valid failure", process: "completed", protocol: "valid", exitCode: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			observation.ProcessStatus = test.process
			observation.ProtocolStatus = test.protocol
			observation.ExitCode = test.exitCode
			if test.process == "completed" {
				observation.ProcessError = ""
			}
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("contradictory observation accepted: %+v", observation)
			}
		})
	}
}

func observationWithoutVerification(observation Observation) Observation {
	observation.VerificationID = ""
	observation.VerificationVer = ""
	observation.ExpectedOutput = ""
	observation.VerificationPass = false
	return observation
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
