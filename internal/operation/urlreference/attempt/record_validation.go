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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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
