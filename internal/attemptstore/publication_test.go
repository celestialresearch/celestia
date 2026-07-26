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
	"reflect"
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
	t.Cleanup(func() { _ = attempt.Close() })
	if err := attempt.Publish(testObservation(accepted.Request.AttemptID)); err != nil {
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
}

func TestInspectRefusesOwnedPublication(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() { _ = attempt.Close() })
	if err := attempt.publishLocked(
		testObservation(accepted.Request.AttemptID),
	); err != nil {
		t.Fatalf("publish while retaining ownership: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrActive) {
		t.Fatalf("active publication inspected: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("close attempt: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect released publication: %v", err)
	}
}

func TestPublishedIdentityCannotRestage(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() { _ = attempt.Close() })
	if err := attempt.Publish(testObservation(accepted.Request.AttemptID)); err != nil {
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
	t.Cleanup(func() { _ = attempt.Close() })
	observation := testObservation(accepted.Request.AttemptID)
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
	t.Cleanup(func() { _ = attempt.Close() })
	observation := testObservation(accepted.Request.AttemptID)
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

func TestRecoverPublishesAfterReceiptFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservation(accepted.Request.AttemptID)
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
	observation := testObservation(accepted.Request.AttemptID)
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
	if err := attempt.Publish(testObservation(accepted.Request.AttemptID)); err != nil {
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
			[]byte(`,"version":0}`)...,
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
			if err := attempt.Publish(testObservation(accepted.Request.AttemptID)); err != nil {
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
			observation := testObservation(accepted.Request.AttemptID)
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
	observation := testObservation(accepted.Request.AttemptID)
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
	base := testObservation(accepted.Request.AttemptID)
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

func TestObservationAcceptsContractTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	verified := testObservation(accepted.Request.AttemptID)
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
	base := observationWithoutVerification(testObservation(accepted.Request.AttemptID))
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

func TestObservationRejectsContradictoryProcessProtocolStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservation(accepted.Request.AttemptID))
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
	observation := testObservation(accepted.Request.AttemptID)
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
			value: testObservation(other.Request.AttemptID),
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

func TestRecordMetadataUsesRequiredFields(t *testing.T) {
	type sample struct {
		Named    string
		Untagged string
		Optional string `json:"optional,omitempty"`
		Ignored  string `json:"-"`
	}
	fields := requiredJSONFields(sample{})
	if len(fields) != 2 || fields[0] != "Named" || fields[1] != "Untagged" {
		t.Fatalf("required fields=%v", fields)
	}
	if err := validateRecord(&sample{}); err != nil {
		t.Fatalf("unrecognised internal record rejected: %v", err)
	}
}

func TestWriteOrMatchRecordRequiresEquality(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	record := Recovery{
		Version:        Version,
		AttemptID:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := writeOrMatchRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := writeOrMatchRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("match record: %v", err)
	}
	record.Reason = "different"
	if err := writeOrMatchRecord(root, recoveryFile, record); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("different duplicate accepted: %v", err)
	}
}

func TestNewRejectsLinkedRoot(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := New(link); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked root accepted: %v", err)
	}
}

func TestPendingPublicationRefusesExistingTarget(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create directory: %v", err)
		}
	}
	if _, err := publishPendingDirectory(source, target, root); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("existing target replaced: %v", err)
	}
	if exists, err := pathExists(filepath.Join(root, "missing")); err != nil || exists {
		t.Fatalf("missing path: exists=%t error=%v", exists, err)
	}
	if exists, err := pathExists(source); err != nil || !exists {
		t.Fatalf("existing path: exists=%t error=%v", exists, err)
	}
	if _, err := pathExists("invalid\x00path"); err == nil {
		t.Fatal("invalid path accepted")
	}
}

func TestPendingPublicationRequiresSource(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	if err := os.RemoveAll(source); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	if err := os.RemoveAll(target); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if _, err := publishPendingDirectory(source, target, root); err == nil {
		t.Fatal("missing source published")
	}
}

func TestCanonicalEvidenceRootRejectsInvalidPath(t *testing.T) {
	if _, err := canonicalEvidenceRoot("invalid\x00path"); err == nil {
		t.Fatal("invalid evidence root accepted")
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

func removeJSONField(t *testing.T, path, field string) {
	t.Helper()
	var record map[string]any
	readJSONFile(t, path, &record)
	delete(record, field)
	writeJSONFile(t, path, record)
}

func replaceJSONField(t *testing.T, path, field string, value any) {
	t.Helper()
	var record map[string]any
	readJSONFile(t, path, &record)
	record[field] = value
	writeJSONFile(t, path, record)
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatalf("open JSON root: %v", err)
	}
	defer func() {
		_ = root.Close()
	}()
	data, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
}
