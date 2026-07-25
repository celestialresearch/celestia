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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"celestia.research/governed-operation/internal/workerprotocol"
)

func requireRecordFields(data []byte, target any) error {
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil {
		return ErrCorrupt
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	for _, name := range requiredJSONFields(target) {
		if _, ok := fields[name]; !ok {
			return ErrCorrupt
		}
	}
	return nil
}

func requiredJSONFields(target any) []string {
	valueType := reflect.TypeOf(target)
	if valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	fields := make([]string, 0, valueType.NumField())
	for field := range valueType.Fields() {
		tag := field.Tag.Get("json")
		name, options, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		if name == "-" || strings.Contains(options, "omitempty") {
			continue
		}
		fields = append(fields, name)
	}
	return fields
}

func validateRecord(target any) error {
	switch record := target.(type) {
	case *Admitted:
		return validateAdmitted(*record)
	case *Observation:
		return validateObservation(*record)
	case *Recovery:
		return validateRecovery(*record)
	case *Receipt:
		return validateReceiptShape(*record)
	case *Publication:
		return validatePublication(*record)
	default:
		return nil
	}
}

func validateAdmitted(record Admitted) error {
	admittedAt, err := time.Parse(time.RFC3339Nano, record.AdmittedAt)
	if err != nil ||
		record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		admittedAt.Location() != time.UTC ||
		len(record.RequestFrame) == 0 {
		return ErrCorrupt
	}
	request, _, err := workerprotocol.DecodeRequest(record.RequestFrame, admittedAt)
	if err != nil {
		return ErrCorrupt
	}
	if record.AttemptID != request.AttemptID ||
		record.OriginalInput != request.Input {
		return ErrCorrupt
	}
	return nil
}

func validateObservation(record Observation) error {
	if record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		!validHash(record.WorkerSHA256) ||
		!validProcessStatus(record.ProcessStatus) ||
		!validProtocolStatus(record.ProtocolStatus) ||
		!validTerminal(record.TerminalStatus) ||
		record.DurationNS < 0 {
		return ErrCorrupt
	}
	return validateObservationTransition(record)
}

func validateObservationTransition(record Observation) error {
	if validObservationTransition(record) {
		return nil
	}
	return ErrCorrupt
}

func validObservationTransition(record Observation) bool {
	switch record.TerminalStatus {
	case "verified":
		return validVerifiedObservation(record)
	case "executed_unverified":
		return validUnverifiedObservation(record)
	case "failed":
		return validFailedObservation(record)
	case "cancelled":
		return record.ProcessStatus == "cancelled" &&
			record.ProtocolStatus == "not_run" &&
			noVerification(record)
	case "timed_out":
		return (record.ProcessStatus == "timed_out" ||
			record.ProcessStatus == "cancelled") &&
			record.ProtocolStatus == "not_run" &&
			noVerification(record)
	default:
		return false
	}
}

func validVerifiedObservation(record Observation) bool {
	return record.ProcessStatus == "completed" &&
		record.ProtocolStatus == "valid" &&
		record.VerificationID != "" &&
		record.VerificationVer != "" &&
		record.ExpectedOutput != "" &&
		record.VerificationPass
}

func validUnverifiedObservation(record Observation) bool {
	return record.ProcessStatus == "completed" &&
		record.ProtocolStatus == "valid" &&
		record.VerificationID != "" &&
		record.VerificationVer != "" &&
		record.ExpectedOutput != "" &&
		!record.VerificationPass
}

func validFailedObservation(record Observation) bool {
	if !noVerification(record) {
		return false
	}
	if record.ProcessStatus == "completed" {
		return record.ProtocolStatus == "valid" ||
			record.ProtocolStatus == "rejected"
	}
	return record.ProtocolStatus == "not_run" &&
		record.ProcessStatus != "cancelled" &&
		record.ProcessStatus != "timed_out"
}

func noVerification(record Observation) bool {
	return record.VerificationID == "" &&
		record.VerificationVer == "" &&
		record.ExpectedOutput == "" &&
		!record.VerificationPass
}

func validateRecovery(record Recovery) error {
	if record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		record.TerminalStatus != "indeterminate" ||
		record.Reason == "" {
		return ErrCorrupt
	}
	return nil
}

func validateReceiptShape(record Receipt) error {
	if record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		record.AdmittedFile != admittedFile ||
		!validHash(record.AdmittedHash) ||
		!validHash(record.TerminalHash) ||
		!validTerminal(record.TerminalState) {
		return ErrCorrupt
	}
	switch record.TerminalKind {
	case "observation":
		if record.TerminalFile != observationFile {
			return ErrCorrupt
		}
	case "recovery":
		if record.TerminalFile != recoveryFile {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	return nil
}

func validatePublication(record Publication) error {
	if record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		!validHash(record.ReceiptHash) {
		return ErrCorrupt
	}
	return nil
}

func validProcessStatus(status string) bool {
	switch status {
	case "completed", "start_failed", "timed_out", "cancelled",
		"output_overflow", "error_overflow", "exit_failed", "cleanup_failed":
		return true
	default:
		return false
	}
}

func validProtocolStatus(status string) bool {
	switch status {
	case "not_run", "valid", "rejected":
		return true
	default:
		return false
	}
}

func publicationExists(path string) (bool, error) {
	var publication Publication
	err := readRecord(path, publicationFile, &publication)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (store *Store) recoverablePath(attemptID string) (string, bool, error) {
	if !validIdentity(attemptID) {
		return "", false, fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	finalPath := store.finalPath(attemptID)
	if exists, err := pathExists(finalPath); err != nil {
		return "", false, err
	} else if exists {
		return finalPath, true, nil
	}
	pendingPath := filepath.Join(store.pendingPath(attemptID), bundleDirectory)
	if exists, err := pathExists(pendingPath); err != nil {
		return "", false, err
	} else if exists {
		return pendingPath, false, nil
	}
	return "", false, os.ErrNotExist
}

func (store *Store) ensureTerminal(path, attemptID, reason string) error {
	var admitted Admitted
	if err := readRecord(path, admittedFile, &admitted); err != nil {
		return err
	}
	if admitted.AttemptID != attemptID {
		return ErrCorrupt
	}
	if err := publishExistingTerminal(path, attemptID); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	recovery := Recovery{
		Version:        Version,
		AttemptID:      attemptID,
		TerminalStatus: "indeterminate",
		Reason:         reason,
	}
	if err := writeOrMatchRecord(path, recoveryFile, recovery); err != nil {
		return err
	}
	return writeOrMatchReceipt(path, attemptID, "recovery", recoveryFile, recovery.TerminalStatus)
}

func publishExistingTerminal(path, attemptID string) error {
	observation, observationErr := readObservationTerminal(path)
	recovery, recoveryErr := readRecoveryTerminal(path)
	observationExists := observationErr == nil
	recoveryExists := recoveryErr == nil
	if observationExists && recoveryExists {
		return ErrCorrupt
	}
	if observationExists {
		if observation.AttemptID != attemptID {
			return ErrCorrupt
		}
		return writeOrMatchReceipt(path, attemptID, "observation", observationFile, observation.TerminalStatus)
	}
	if recoveryExists {
		if recovery.AttemptID != attemptID {
			return ErrCorrupt
		}
		return writeOrMatchReceipt(path, attemptID, "recovery", recoveryFile, recovery.TerminalStatus)
	}
	if errors.Is(observationErr, os.ErrNotExist) && errors.Is(recoveryErr, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if !errors.Is(observationErr, os.ErrNotExist) {
		return observationErr
	}
	return recoveryErr
}

func readObservationTerminal(path string) (Observation, error) {
	var observation Observation
	if err := readRecord(path, observationFile, &observation); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func readRecoveryTerminal(path string) (Recovery, error) {
	var recovery Recovery
	if err := readRecord(path, recoveryFile, &recovery); err != nil {
		return Recovery{}, err
	}
	return recovery, nil
}
