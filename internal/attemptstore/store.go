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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"celestia.research/governed-operation/internal/urladmission"
)

const Version = 0

var (
	ErrInvalid   = errors.New("invalid attempt evidence")
	ErrDuplicate = errors.New("duplicate attempt")
	ErrCorrupt   = errors.New("corrupt attempt evidence")
	identity     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type Admitted struct {
	Version       int    `json:"version"`
	AttemptID     string `json:"attempt_id"`
	AdmittedAt    string `json:"admitted_at"`
	OriginalInput string `json:"original_input"`
	RequestFrame  []byte `json:"request_frame"`
}

type Observation struct {
	Version          int    `json:"version"`
	AttemptID        string `json:"attempt_id"`
	WorkerSHA256     string `json:"worker_sha256"`
	ProcessStatus    string `json:"process_status"`
	ProcessError     string `json:"process_error,omitempty"`
	ExitCode         uint32 `json:"exit_code"`
	Stdout           []byte `json:"stdout"`
	Stderr           []byte `json:"stderr"`
	CleanupComplete  bool   `json:"cleanup_complete"`
	ProtocolStatus   string `json:"protocol_status"`
	VerificationID   string `json:"verification_id,omitempty"`
	VerificationVer  string `json:"verification_version,omitempty"`
	ExpectedOutput   string `json:"expected_output,omitempty"`
	VerificationPass bool   `json:"verification_pass"`
	TerminalStatus   string `json:"terminal_status"`
	DurationNS       int64  `json:"duration_ns"`
}

type Recovery struct {
	Version        int    `json:"version"`
	AttemptID      string `json:"attempt_id"`
	TerminalStatus string `json:"terminal_status"`
	Reason         string `json:"reason"`
}

type Receipt struct {
	Version       int    `json:"version"`
	AttemptID     string `json:"attempt_id"`
	TerminalKind  string `json:"terminal_kind"`
	AdmittedFile  string `json:"admitted_file"`
	AdmittedHash  string `json:"admitted_sha256"`
	TerminalFile  string `json:"terminal_file"`
	TerminalHash  string `json:"terminal_sha256"`
	TerminalState string `json:"terminal_status"`
}

type Records struct {
	Admitted    Admitted
	Observation *Observation
	Recovery    *Recovery
	Receipt     Receipt
}

type Store struct {
	root string
}

type Attempt struct {
	path     string
	admitted Admitted
}

func New(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("%w: evidence root", ErrInvalid)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence root: %w", err)
	}
	return &Store{root: filepath.Clean(root)}, nil
}

func (store *Store) Stage(accepted urladmission.Accepted, admittedAt time.Time) (*Attempt, error) {
	if !identity.MatchString(accepted.Request.AttemptID) ||
		admittedAt.Location() != time.UTC ||
		len(accepted.Frame) == 0 {
		return nil, fmt.Errorf("%w: admitted attempt", ErrInvalid)
	}
	path := filepath.Join(store.root, accepted.Request.AttemptID)
	if err := os.Mkdir(path, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("create attempt: %w", err)
	}
	admitted := Admitted{
		Version:       Version,
		AttemptID:     accepted.Request.AttemptID,
		AdmittedAt:    admittedAt.Format(time.RFC3339Nano),
		OriginalInput: accepted.Request.Input,
		RequestFrame:  accepted.Frame,
	}
	if err := writeRecord(path, "admitted.json", admitted); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("stage attempt: %w", err)
	}
	return &Attempt{path: path, admitted: admitted}, nil
}

func (attempt *Attempt) Publish(observation Observation) error {
	if observation.Version != Version ||
		observation.AttemptID != attempt.admitted.AttemptID ||
		!validTerminal(observation.TerminalStatus) ||
		!validHash(observation.WorkerSHA256) {
		return fmt.Errorf("%w: observation", ErrInvalid)
	}
	if err := writeRecord(attempt.path, "observation.json", observation); err != nil {
		return fmt.Errorf("write observation: %w", err)
	}
	return publishReceipt(
		attempt.path,
		attempt.admitted.AttemptID,
		"observation",
		"observation.json",
		observation.TerminalStatus,
	)
}

func (store *Store) Recover(attemptID, reason string) error {
	path, err := store.attemptPath(attemptID)
	if err != nil {
		return err
	}
	if reason == "" {
		return fmt.Errorf("%w: recovery reason", ErrInvalid)
	}
	if _, err := os.Stat(filepath.Join(path, "receipt.json")); err == nil {
		return ErrDuplicate
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect receipt: %w", err)
	}
	recovery := Recovery{
		Version:        Version,
		AttemptID:      attemptID,
		TerminalStatus: "indeterminate",
		Reason:         reason,
	}
	if err := writeRecord(path, "recovery.json", recovery); err != nil {
		return fmt.Errorf("write recovery: %w", err)
	}
	return publishReceipt(path, attemptID, "recovery", "recovery.json", "indeterminate")
}

func (store *Store) Inspect(attemptID string) (Records, error) {
	path, err := store.attemptPath(attemptID)
	if err != nil {
		return Records{}, err
	}
	var records Records
	if err := readRecord(path, "admitted.json", &records.Admitted); err != nil {
		return Records{}, err
	}
	if err := readRecord(path, "receipt.json", &records.Receipt); err != nil {
		return Records{}, err
	}
	if err := validateReceipt(attemptID, records.Admitted, records.Receipt); err != nil {
		return Records{}, err
	}
	if err := verifyHash(path, records.Receipt.AdmittedFile, records.Receipt.AdmittedHash); err != nil {
		return Records{}, err
	}
	if err := verifyHash(path, records.Receipt.TerminalFile, records.Receipt.TerminalHash); err != nil {
		return Records{}, err
	}
	if err := loadTerminal(path, &records); err != nil {
		return Records{}, err
	}
	return records, nil
}

func validateReceipt(attemptID string, admitted Admitted, receipt Receipt) error {
	if admitted.AttemptID != attemptID ||
		receipt.AttemptID != attemptID ||
		receipt.AdmittedFile != "admitted.json" {
		return ErrCorrupt
	}
	switch receipt.TerminalKind {
	case "observation":
		if receipt.TerminalFile != "observation.json" {
			return ErrCorrupt
		}
	case "recovery":
		if receipt.TerminalFile != "recovery.json" {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	return nil
}

func loadTerminal(path string, records *Records) error {
	switch records.Receipt.TerminalKind {
	case "observation":
		var observation Observation
		if err := readRecord(path, records.Receipt.TerminalFile, &observation); err != nil {
			return err
		}
		if observation.AttemptID != records.Receipt.AttemptID ||
			observation.TerminalStatus != records.Receipt.TerminalState {
			return ErrCorrupt
		}
		records.Observation = &observation
	case "recovery":
		var recovery Recovery
		if err := readRecord(path, records.Receipt.TerminalFile, &recovery); err != nil {
			return err
		}
		if recovery.AttemptID != records.Receipt.AttemptID ||
			recovery.TerminalStatus != records.Receipt.TerminalState {
			return ErrCorrupt
		}
		records.Recovery = &recovery
	}
	return nil
}

func (store *Store) attemptPath(attemptID string) (string, error) {
	if !identity.MatchString(attemptID) {
		return "", fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	path := filepath.Join(store.root, attemptID)
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect attempt: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrCorrupt
	}
	return path, nil
}

func publishReceipt(path, attemptID, kind, terminalFile, state string) error {
	admittedHash, err := fileHash(path, "admitted.json")
	if err != nil {
		return err
	}
	terminalHash, err := fileHash(path, terminalFile)
	if err != nil {
		return err
	}
	receipt := Receipt{
		Version:       Version,
		AttemptID:     attemptID,
		TerminalKind:  kind,
		AdmittedFile:  "admitted.json",
		AdmittedHash:  admittedHash,
		TerminalFile:  terminalFile,
		TerminalHash:  terminalHash,
		TerminalState: state,
	}
	return writeRecord(path, "receipt.json", receipt)
}

func writeRecord(path, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(path, "."+name+".*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	target := filepath.Join(path, name)
	if _, err := os.Stat(target); err == nil {
		return ErrDuplicate
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := publishFile(temporaryName, target, path); err != nil {
		return err
	}
	return nil
}

func readRecord(path, name string, target any) error {
	data, err := readRooted(path, name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrCorrupt
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	return nil
}

func verifyHash(path, name, expected string) error {
	actual, err := fileHash(path, name)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrCorrupt
	}
	return nil
}

func fileHash(path, name string) (string, error) {
	data, err := readRooted(path, name)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func readRooted(path, name string) ([]byte, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCorrupt
	}
	return io.ReadAll(file)
}

func validTerminal(status string) bool {
	switch status {
	case "failed", "executed_unverified", "verified", "indeterminate":
		return true
	default:
		return false
	}
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
