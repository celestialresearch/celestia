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
	"reflect"
	"sync"
	"time"

	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/workerprotocol"
)

const Version = 0

const (
	attemptsDirectory = "attempts"
	pendingDirectory  = ".pending"
	locksDirectory    = ".locks"
	bundleDirectory   = "bundle"
	publicationFile   = "publication.json"
	receiptFile       = "receipt.json"
	admittedFile      = "admitted.json"
	observationFile   = "observation.json"
	recoveryFile      = "recovery.json"

	maxRecordBytes = 256 * 1024
)

var (
	ErrInvalid           = errors.New("invalid attempt evidence")
	ErrDuplicate         = errors.New("duplicate attempt")
	ErrCorrupt           = errors.New("corrupt attempt evidence")
	ErrActive            = errors.New("attempt is active")
	ErrRelease           = errors.New("attempt ownership release failed")
	ErrMigrationRequired = errors.New("attempt evidence migration required")
	ErrUnsupported       = errors.New("attempt evidence is unsupported")
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

type Publication struct {
	Version     int    `json:"version"`
	AttemptID   string `json:"attempt_id"`
	ReceiptHash string `json:"receipt_sha256"`
}

type Records struct {
	Admitted    Admitted
	Observation *Observation
	Recovery    *Recovery
	Receipt     Receipt
	Publication Publication
}

type Store struct {
	root         string
	lockIdentity os.FileInfo
}

type Attempt struct {
	mu          sync.Mutex
	store       *Store
	path        string
	pendingPath string
	admitted    Admitted
	owner       *attemptLock
	closed      bool
}

func New(root string) (*Store, error) {
	clean, err := prepareEvidenceRoot(root)
	if err != nil {
		return nil, err
	}
	if err := prepareEvidenceDirectories(clean); err != nil {
		return nil, err
	}
	lockDirectoryCreated, err := createLockDirectory(clean)
	if err != nil {
		return nil, fmt.Errorf("create attempt locks: %w", err)
	}
	if err := validateEvidenceDirectories(clean); err != nil {
		return nil, err
	}
	if lockDirectoryCreated {
		if err := syncAttemptLockDirectory(clean); err != nil {
			return nil, fmt.Errorf("sync attempt locks: %w", err)
		}
	}
	lockIdentity, err := lstatEvidencePath(filepath.Join(clean, locksDirectory))
	if err != nil {
		return nil, fmt.Errorf("inspect attempt locks: %w", err)
	}
	return &Store{root: clean, lockIdentity: lockIdentity}, nil
}

func (store *Store) Stage(
	accepted urladmission.Accepted,
	admittedAt time.Time,
) (attempt *Attempt, err error) {
	request, err := validateAccepted(accepted, admittedAt)
	if err != nil {
		return nil, err
	}
	if err := store.rejectDuplicateAttempt(request.AttemptID); err != nil {
		return nil, err
	}
	owner, err := store.acquireAttemptLock(request.AttemptID, true)
	if err != nil {
		return nil, err
	}
	keepOwner := false
	defer func() {
		if !keepOwner {
			err = publishResult(err, owner.release())
		}
	}()
	if err := store.createOwnershipMarker(request.AttemptID); err != nil {
		return nil, err
	}
	pendingPath, path, err := store.prepareAttemptDirectories(request.AttemptID)
	if err != nil {
		return nil, err
	}
	admitted := admittedRecord(request, accepted.Frame, admittedAt)
	if err := writeRecord(path, admittedFile, admitted); err != nil {
		_ = os.RemoveAll(pendingPath)
		return nil, fmt.Errorf("stage attempt: %w", err)
	}
	attempt = &Attempt{
		store:       store,
		path:        path,
		pendingPath: pendingPath,
		admitted:    admitted,
		owner:       owner,
	}
	keepOwner = true
	return attempt, nil
}

func (store *Store) rejectDuplicateAttempt(attemptID string) error {
	for _, path := range []string{
		store.finalPath(attemptID),
		store.pendingPath(attemptID),
	} {
		exists, err := pathExists(path)
		if err != nil {
			return fmt.Errorf("inspect attempt: %w", err)
		}
		if exists {
			return ErrDuplicate
		}
	}
	return nil
}

func (store *Store) prepareAttemptDirectories(attemptID string) (string, string, error) {
	if exists, err := pathExists(store.finalPath(attemptID)); err != nil {
		return "", "", fmt.Errorf("inspect published attempt: %w", err)
	} else if exists {
		return "", "", ErrDuplicate
	}
	pendingPath := store.pendingPath(attemptID)
	if err := createEvidenceDirectory(pendingPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", "", ErrDuplicate
		}
		return "", "", fmt.Errorf("create attempt: %w", err)
	}
	path := filepath.Join(pendingPath, bundleDirectory)
	if err := createEvidenceDirectory(path); err != nil {
		_ = os.RemoveAll(pendingPath)
		return "", "", fmt.Errorf("create attempt bundle: %w", err)
	}
	return pendingPath, path, nil
}

func validateAccepted(
	accepted urladmission.Accepted,
	admittedAt time.Time,
) (workerprotocol.Request, error) {
	if admittedAt.Location() != time.UTC || len(accepted.Frame) == 0 {
		return workerprotocol.Request{}, fmt.Errorf("%w: admitted attempt", ErrInvalid)
	}
	request, _, err := workerprotocol.DecodeRequest(accepted.Frame, admittedAt)
	if err != nil {
		return workerprotocol.Request{}, fmt.Errorf("%w: admitted request frame: %w", ErrInvalid, err)
	}
	if request != accepted.Request {
		return workerprotocol.Request{}, fmt.Errorf("%w: accepted request binding", ErrInvalid)
	}
	return request, nil
}

func admittedRecord(
	request workerprotocol.Request,
	frame []byte,
	admittedAt time.Time,
) Admitted {
	return Admitted{
		Version:       Version,
		AttemptID:     request.AttemptID,
		AdmittedAt:    admittedAt.Format(time.RFC3339Nano),
		OriginalInput: request.Input,
		RequestFrame:  frame,
	}
}

func (attempt *Attempt) Publish(observation Observation) error {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.closed {
		return fmt.Errorf("%w: attempt ownership released", ErrInvalid)
	}
	err := attempt.publishLocked(observation)
	return publishResult(err, attempt.closeLocked())
}

func (attempt *Attempt) publishLocked(observation Observation) error {
	if err := validateObservation(observation); err != nil ||
		observation.AttemptID != attempt.admitted.AttemptID {
		return fmt.Errorf("%w: observation", ErrInvalid)
	}
	if err := writeOrMatchRecord(attempt.path, observationFile, observation); err != nil {
		return fmt.Errorf("write observation: %w", err)
	}
	if err := writeOrMatchReceipt(
		attempt.path,
		attempt.admitted.AttemptID,
		"observation",
		observationFile,
		observation.TerminalStatus,
	); err != nil {
		return err
	}
	path, err := attempt.publishDirectory()
	if err != nil {
		return err
	}
	return publishMarker(path, attempt.admitted.AttemptID)
}

func (store *Store) Recover(attemptID, reason string) (err error) {
	if reason == "" {
		return fmt.Errorf("%w: recovery reason", ErrInvalid)
	}
	if _, _, err := store.recoverablePath(attemptID); err != nil {
		return err
	}
	owner, err := store.acquireAttemptLock(attemptID, false)
	if err != nil {
		if errors.Is(err, ErrCorrupt) || errors.Is(err, os.ErrNotExist) {
			legacy, legacyErr := store.legacyLockMissing(attemptID)
			if legacyErr != nil {
				return legacyErr
			}
			if legacy {
				return fmt.Errorf("%w: attempt %s has no v0 ownership lock", ErrMigrationRequired, attemptID)
			}
			return ErrCorrupt
		}
		return err
	}
	return store.recoverOwned(attemptID, reason, owner)
}

// MigrateV0 explicitly adopts a pre-lock v0 attempt after its caller has
// quiesced every writer that could still own the legacy bundle.
func (store *Store) MigrateV0(attemptID, reason string) (err error) {
	if reason == "" {
		return fmt.Errorf("%w: migration reason", ErrInvalid)
	}
	legacy, err := store.legacyLockMissing(attemptID)
	if err != nil {
		return err
	}
	if !legacy {
		return fmt.Errorf("%w: v0 lock is present", ErrInvalid)
	}
	owner, err := store.acquireAttemptLock(attemptID, true)
	if err != nil {
		return err
	}
	if err := store.createOwnershipMarker(attemptID); err != nil {
		return publishResult(err, owner.release())
	}
	return store.recoverOwned(attemptID, reason, owner)
}

func (store *Store) recoverOwned(attemptID, reason string, owner *attemptLock) (err error) {
	defer func() {
		err = publishResult(err, owner.release())
	}()
	path, final, err := store.recoverablePath(attemptID)
	if err != nil {
		return err
	}
	if published, err := publicationExists(path, attemptID); err != nil {
		return err
	} else if published {
		return ErrDuplicate
	}
	if err := store.ensureTerminal(path, attemptID, reason); err != nil {
		return err
	}
	if !final {
		pendingPath := store.pendingPath(attemptID)
		path, err = publishPendingDirectory(path, store.finalPath(attemptID), store.attemptsPath())
		if err != nil {
			return err
		}
		if err := removePendingDirectory(pendingPath); err != nil {
			return err
		}
	}
	return publishMarker(path, attemptID)
}

func (store *Store) legacyLockMissing(attemptID string) (bool, error) {
	if !validIdentity(attemptID) {
		return false, nil
	}
	marker, err := store.hasOwnershipMarker(attemptID)
	if err != nil || marker {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(store.root, locksDirectory, attemptID+".lock")); !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	_, _, err = store.recoverablePath(attemptID)
	return err == nil, err
}

func publishResult(publicationErr, releaseErr error) error {
	if releaseErr == nil {
		return publicationErr
	}
	if publicationErr == nil {
		return fmt.Errorf("%w: %w", ErrRelease, releaseErr)
	}
	return errors.Join(
		publicationErr,
		fmt.Errorf("%w: %w", ErrRelease, releaseErr),
	)
}

func (attempt *Attempt) Close() error {
	if attempt == nil {
		return nil
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	return attempt.closeLocked()
}

func (attempt *Attempt) closeLocked() error {
	if attempt.closed || attempt.owner == nil {
		return nil
	}
	attempt.closed = true
	return attempt.owner.release()
}

func (store *Store) Inspect(attemptID string) (Records, error) {
	path, err := store.attemptPath(attemptID)
	if err != nil {
		return Records{}, err
	}
	records, err := readBundle(path, attemptID)
	if err != nil {
		return Records{}, err
	}
	if err := readRecord(path, publicationFile, &records.Publication); err != nil {
		return Records{}, err
	}
	if records.Publication.AttemptID != attemptID {
		return Records{}, ErrCorrupt
	}
	if err := verifyHash(path, receiptFile, records.Publication.ReceiptHash); err != nil {
		return Records{}, err
	}
	return records, nil
}

func readBundle(path, attemptID string) (Records, error) {
	var records Records
	if err := readRecord(path, admittedFile, &records.Admitted); err != nil {
		return Records{}, err
	}
	if err := readRecord(path, receiptFile, &records.Receipt); err != nil {
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
	if validateAdmitted(admitted) != nil ||
		validateReceiptShape(receipt) != nil ||
		admitted.AttemptID != attemptID ||
		receipt.AttemptID != attemptID {
		return ErrCorrupt
	}
	return nil
}

func (attempt *Attempt) publishDirectory() (string, error) {
	if attempt.pendingPath == "" {
		return attempt.path, nil
	}
	path, err := publishPendingDirectory(
		attempt.path,
		attempt.store.finalPath(attempt.admitted.AttemptID),
		attempt.store.attemptsPath(),
	)
	if err != nil {
		return "", err
	}
	pendingPath := attempt.pendingPath
	attempt.path = path
	attempt.pendingPath = ""
	if err := removePendingDirectory(pendingPath); err != nil {
		return "", err
	}
	return path, nil
}

func removePendingDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pending attempt: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || pathIsLinked(path, info) {
		return ErrCorrupt
	}
	if err := secureEvidenceTree(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove pending attempt: %w", err)
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
	if !validIdentity(attemptID) {
		return "", fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	path := store.finalPath(attemptID)
	if err := rejectLinkedAncestors(path); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect attempt: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || pathIsLinked(path, info) {
		return "", ErrCorrupt
	}
	return path, nil
}

func writeOrMatchReceipt(path, attemptID, kind, terminalFile, state string) error {
	admittedHash, err := fileHash(path, admittedFile)
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
		AdmittedFile:  admittedFile,
		AdmittedHash:  admittedHash,
		TerminalFile:  terminalFile,
		TerminalHash:  terminalHash,
		TerminalState: state,
	}
	return writeOrMatchRecord(path, receiptFile, receipt)
}

func publishMarker(path, attemptID string) error {
	if _, err := readBundle(path, attemptID); err != nil {
		return fmt.Errorf("verify published bundle: %w", err)
	}
	receiptHash, err := fileHash(path, receiptFile)
	if err != nil {
		return err
	}
	publication := Publication{
		Version:     Version,
		AttemptID:   attemptID,
		ReceiptHash: receiptHash,
	}
	if err := writeRecord(path, publicationFile, publication); err != nil {
		return fmt.Errorf("write publication: %w", err)
	}
	return nil
}

func writeRecord(path, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxRecordBytes {
		return fmt.Errorf("%w: record exceeds limit", ErrInvalid)
	}
	temporary, err := createRecordTemp(path, name)
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

func writeOrMatchRecord(path, name string, value any) error {
	err := writeRecord(path, name, value)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrDuplicate) {
		return err
	}
	existing := reflect.New(reflect.TypeOf(value)).Interface()
	if readErr := readRecord(path, name, existing); readErr != nil {
		return readErr
	}
	if !reflect.DeepEqual(reflect.ValueOf(existing).Elem().Interface(), value) {
		return ErrDuplicate
	}
	return nil
}

func readRecord(path, name string, target any) error {
	data, err := readRooted(path, name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if err := requireRecordFields(data, target); err != nil {
		return err
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
	return validateRecord(target)
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
	if err := rejectLinkedAncestors(path); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if invalidRecordFile(filepath.Join(path, name), info) {
		return nil, ErrCorrupt
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if invalidRecordFile(filepath.Join(path, name), info) {
		return nil, ErrCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, ErrCorrupt
	}
	return data, nil
}
