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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"celestia.research/celestia/internal/operation/urlreference/transform"
	"celestia.research/celestia/internal/workerprotocolv1"
)

func invalidRecordFile(path string, info os.FileInfo) bool {
	return !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		pathIsLinked(path, info) ||
		info.Size() > maxRecordBytes ||
		secureEvidenceFile(path) != nil
}

func validTerminal(status string) bool {
	switch status {
	case "failed", "cancelled", "timed_out",
		"executed_unverified", "verified", "indeterminate":
		return true
	default:
		return false
	}
}

func validIdentity(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

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
		admittedAt.Location() != time.UTC ||
		admittedAt.Format(time.RFC3339Nano) != record.AdmittedAt ||
		len(record.RequestFrame) == 0 {
		return ErrCorrupt
	}
	var request requestV1
	switch record.Version {
	case Version:
		request, err = decodeRequestV1(record.RequestFrame, admittedAt)
	default:
		return ErrCorrupt
	}
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
		record.DurationNS < 0 {
		return ErrCorrupt
	}
	return validateObservationTransition(record)
}

func validateObservationEvidence(admitted Admitted, observation Observation) error {
	return validateObservationEvidenceWith(admitted, observation, validateVerificationEvidence)
}

func validateRetainedObservationEvidence(admitted Admitted, observation Observation) error {
	return validateObservationEvidenceWith(
		admitted,
		observation,
		validateRetainedVerificationEvidence,
	)
}

func validateObservationEvidenceWith(
	admitted Admitted,
	observation Observation,
	validateVerification func(workerprotocol.Request, workerprotocol.Response, Observation) error,
) error {
	if len(observation.Stdout) > workerprotocol.MaxResponseBytes ||
		len(observation.Stderr) > workerprotocol.StderrBytes {
		return ErrCorrupt
	}
	if observation.ProtocolStatus == "not_run" {
		return nil
	}
	request, response, responseErr := decodeObservationEvidence(admitted, observation)
	switch observation.ProtocolStatus {
	case "valid":
		if responseErr != nil {
			return ErrCorrupt
		}
		return validateVerification(request, response, observation)
	case "rejected":
		if responseErr == nil {
			return ErrCorrupt
		}
	}
	return nil
}

func validateRetainedVerificationEvidence(
	_ workerprotocol.Request,
	response workerprotocol.Response,
	observation Observation,
) error {
	if response.Status != workerprotocol.Completed {
		return nil
	}
	if observation.VerificationID != URLVerifierID ||
		observation.VerificationVer != URLVerifierVersion ||
		observation.ExpectedOutput == "" ||
		observation.VerificationPass != (*response.Output == observation.ExpectedOutput) {
		return ErrCorrupt
	}
	return nil
}

func decodeObservationEvidence(
	admitted Admitted,
	observation Observation,
) (workerprotocol.Request, workerprotocol.Response, error) {
	admittedAt, err := time.Parse(time.RFC3339Nano, admitted.AdmittedAt)
	if err != nil {
		return workerprotocol.Request{}, workerprotocol.Response{}, err
	}
	retained, err := decodeRequestV1(admitted.RequestFrame, admittedAt)
	if err != nil {
		return workerprotocol.Request{}, workerprotocol.Response{}, err
	}
	request := retained.workerRequest()
	response, err := workerprotocol.DecodeResponseForRequestCorrelation(
		observation.Stdout,
		request,
		int(observation.ExitCode),
	)
	return request, response, err
}

func validateVerificationEvidence(
	request workerprotocol.Request,
	response workerprotocol.Response,
	observation Observation,
) error {
	if response.Status != workerprotocol.Completed {
		return nil
	}
	expected, err := urlreference.Transform(
		request.Input,
		urlreference.Mode(request.Mode),
	)
	if err != nil ||
		observation.VerificationID != URLVerifierID ||
		observation.VerificationVer != URLVerifierVersion ||
		observation.ExpectedOutput != expected ||
		observation.VerificationPass != (*response.Output == expected) {
		return ErrCorrupt
	}
	return nil
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
		return validCancelledObservation(record)
	case "timed_out":
		return validTimedOutObservation(record)
	default:
		return false
	}
}

func validCancelledObservation(record Observation) bool {
	return record.ProcessStatus == "cancelled" &&
		record.ProcessError != "" &&
		record.ProtocolStatus == "not_run" &&
		noVerification(record)
}

func validTimedOutObservation(record Observation) bool {
	return (record.ProcessStatus == "timed_out" ||
		record.ProcessStatus == "cancelled" ||
		record.ProcessStatus == "start_failed") &&
		record.ProcessError != "" &&
		record.ProtocolStatus == "not_run" &&
		noVerification(record) &&
		(record.ProcessStatus != "start_failed" ||
			record.ExitCode == 0 && noProcessStreams(record))
}

func validVerifiedObservation(record Observation) bool {
	return record.ProcessStatus == "completed" &&
		record.ProcessError == "" &&
		record.ExitCode == 0 &&
		record.CleanupComplete &&
		record.ProtocolStatus == "valid" &&
		record.VerificationID != "" &&
		record.VerificationVer != "" &&
		record.ExpectedOutput != "" &&
		record.VerificationPass
}

func validUnverifiedObservation(record Observation) bool {
	return record.ProcessStatus == "completed" &&
		record.ProcessError == "" &&
		record.ExitCode == 0 &&
		record.CleanupComplete &&
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
	if !record.CleanupComplete {
		return validCleanupImpairedFailure(record)
	}
	switch record.ProcessStatus {
	case "completed":
		return validCompletedFailure(record)
	case "cleanup_failed":
		return validCleanupFailure(record)
	case "start_failed":
		return validStartFailure(record)
	case "exit_failed":
		return validExitFailure(record)
	case "output_overflow", "error_overflow":
		return validProcessFailure(record)
	default:
		return false
	}
}

func validCleanupImpairedFailure(record Observation) bool {
	if record.ProcessError == "" || record.ProtocolStatus != "not_run" {
		return false
	}
	switch record.ProcessStatus {
	case "completed", "exit_failed", "output_overflow", "error_overflow", "cleanup_failed":
		return true
	case "start_failed":
		return record.ExitCode == 0 && noProcessStreams(record)
	default:
		return false
	}
}

func validCompletedFailure(record Observation) bool {
	if record.ProcessError != "" || !record.CleanupComplete {
		return false
	}
	switch record.ProtocolStatus {
	case "valid":
		return record.ExitCode == 2
	case "rejected":
		return record.ExitCode == 0 ||
			record.ExitCode == 2 ||
			record.ExitCode == 3
	default:
		return false
	}
}

func validExitFailure(record Observation) bool {
	if record.ProcessError == "" || !record.CleanupComplete {
		return false
	}
	if record.ProtocolStatus == "valid" {
		return record.ExitCode == 3
	}
	return record.ProtocolStatus == "not_run"
}

func validCleanupFailure(record Observation) bool {
	return record.ProtocolStatus == "not_run" &&
		record.ProcessError != "" &&
		!record.CleanupComplete
}

func validStartFailure(record Observation) bool {
	return record.ProtocolStatus == "not_run" &&
		record.ProcessError != "" &&
		record.CleanupComplete &&
		record.ExitCode == 0 &&
		noProcessStreams(record)
}

func validProcessFailure(record Observation) bool {
	return record.ProtocolStatus == "not_run" &&
		record.ProcessError != "" &&
		record.CleanupComplete
}

func noVerification(record Observation) bool {
	return record.VerificationID == "" &&
		record.VerificationVer == "" &&
		record.ExpectedOutput == "" &&
		!record.VerificationPass
}

func noProcessStreams(record Observation) bool {
	return len(record.Stdout) == 0 && len(record.Stderr) == 0
}

func validateRecovery(record Recovery) error {
	if record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		record.TerminalStatus != "indeterminate" ||
		!validRecoveryReason(record.Reason) {
		return ErrCorrupt
	}
	return nil
}

func validRecoveryReason(reason string) bool {
	if len(reason) == 0 ||
		len(reason) > maxRecoveryReasonBytes ||
		!utf8.ValidString(reason) ||
		strings.TrimSpace(reason) != reason {
		return false
	}
	for _, value := range reason {
		if unicode.IsControl(value) {
			return false
		}
	}
	return true
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

func publicationExists(path, attemptID string) (bool, error) {
	var publication Publication
	err := readRecord(path, publicationFile, &publication)
	if err == nil {
		if publication.AttemptID != attemptID {
			return false, ErrCorrupt
		}
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (store *Store) recoverablePath(attemptID string) (string, bool, error) {
	return store.recoverablePathWith(attemptID, pathExists, confirmPublication)
}

func (store *Store) recoverablePathWith(
	attemptID string,
	existsAt func(string) (bool, error),
	confirm func(string) error,
) (string, bool, error) {
	if !validIdentity(attemptID) {
		return "", false, fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	finalPath := store.finalPath(attemptID)
	if exists, err := existsAt(finalPath); err != nil {
		return "", false, err
	} else if exists {
		if err := confirm(store.attemptsPath()); err != nil {
			return "", false, fmt.Errorf("confirm attempt publication: %w", err)
		}
		return finalPath, true, nil
	}
	pendingPath := filepath.Join(store.pendingPath(attemptID), bundleDirectory)
	if exists, err := existsAt(pendingPath); err != nil {
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
	return ensureTerminalWith(
		path,
		attemptID,
		reason,
		publishExistingTerminal,
		writeOrMatchRecord,
		writeOrMatchReceipt,
	)
}

func ensureTerminalWith(
	path string,
	attemptID string,
	reason string,
	publishExisting func(string, string) error,
	writeRecovery func(string, string, any) error,
	writeReceipt func(string, string, string, string, string) error,
) error {
	if err := publishExisting(path, attemptID); err == nil {
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
	if err := writeRecovery(path, recoveryFile, recovery); err != nil {
		return err
	}
	return writeReceipt(path, attemptID, "recovery", recoveryFile, recovery.TerminalStatus)
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
		if !errors.Is(recoveryErr, os.ErrNotExist) {
			return recoveryErr
		}
		if observation.AttemptID != attemptID {
			return ErrCorrupt
		}
		return writeOrMatchReceipt(path, attemptID, "observation", observationFile, observation.TerminalStatus)
	}
	if recoveryExists {
		if !errors.Is(observationErr, os.ErrNotExist) {
			return observationErr
		}
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
