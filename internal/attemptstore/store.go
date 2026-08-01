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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"celestia.research/celestia/internal/urladmission"
	"celestia.research/celestia/internal/workerprotocolv1"
)

const Version = 1

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

	maxRecordBytes         = 256 * 1024
	maxRecoveryReasonBytes = 512
)

var (
	ErrInvalid     = errors.New("invalid attempt evidence")
	ErrDuplicate   = errors.New("duplicate attempt")
	ErrCorrupt     = errors.New("corrupt attempt evidence")
	ErrActive      = errors.New("attempt is active")
	ErrUncommitted = errors.New("attempt staging did not commit")
	ErrRelease     = errors.New("attempt ownership release failed")
	ErrPublication = errors.New("attempt publication failed")
	ErrUnsupported = errors.New("attempt evidence is unsupported")
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
	receiptHash string
}

type Store struct {
	root         string
	lockIdentity os.FileInfo
}

type storeCreationOperations struct {
	prepareRoot         func(string) (string, error)
	prepareDirectories  func(string) error
	createLock          func(string) (bool, error)
	validateDirectories func(string) error
	syncLocks           func(string) error
	lstat               func(string) (os.FileInfo, error)
}

type pendingPublicationOperations struct {
	publish func(string, string, string) (string, error)
	remove  func(string) error
}

type pendingRemovalOperations struct {
	lstat  func(string) (os.FileInfo, error)
	linked func(string, os.FileInfo) bool
	secure func(string) error
	remove func(string) error
}

type markerPublicationOperations struct {
	read     func(string, string) (Records, error)
	validate func(string, string, bool) error
	write    func(string, string, any) error
}

type recoveryOperations struct {
	recoverable func(string) (string, bool, error)
	acquire     func(string, bool) (*attemptLock, error)
	marker      func(string) (bool, error)
	remove      func(string) error
	release     func(*attemptLock) error
	owned       func(string, string, *attemptLock) error
}

type ownedRecoveryOperations struct {
	recoverable func(string) (string, bool, error)
	repair      func(string) error
	published   func(string, string) (bool, error)
	recover     func(string, string) error
	terminal    func(string, string, string) error
	publish     func(string, string, string) (string, error)
	remove      func(string) error
	marker      func(string, string) error
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

type CommittedStageError struct {
	AttemptID string
	Err       error
}

func (failure *CommittedStageError) Error() string {
	return fmt.Sprintf(
		"attempt %s committed before staging failed: %v",
		failure.AttemptID,
		failure.Err,
	)
}

func (failure *CommittedStageError) Unwrap() error {
	return failure.Err
}

func New(root string) (*Store, error) {
	return newStoreWith(root, storeCreationOperations{
		prepareRoot:         prepareEvidenceRoot,
		prepareDirectories:  prepareEvidenceDirectories,
		createLock:          createLockDirectory,
		validateDirectories: validateEvidenceDirectories,
		syncLocks:           syncAttemptLockDirectory,
		lstat:               lstatEvidencePath,
	})
}

func newStoreWith(
	root string,
	operations storeCreationOperations,
) (*Store, error) {
	clean, err := operations.prepareRoot(root)
	if err != nil {
		return nil, err
	}
	if err := operations.prepareDirectories(clean); err != nil {
		return nil, err
	}
	lockDirectoryCreated, err := operations.createLock(clean)
	if err != nil {
		return nil, fmt.Errorf("create attempt locks: %w", err)
	}
	if err := operations.validateDirectories(clean); err != nil {
		return nil, err
	}
	if lockDirectoryCreated {
		if err := operations.syncLocks(clean); err != nil {
			return nil, fmt.Errorf("sync attempt locks: %w", err)
		}
	}
	lockIdentity, err := operations.lstat(filepath.Join(clean, locksDirectory))
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
	attempt, err = store.stageOwned(
		accepted, request, admittedAt, owner, writeRecord,
		store.createOwnershipMarkerState,
	)
	if err != nil {
		return nil, err
	}
	keepOwner = true
	return attempt, nil
}

func (store *Store) stageOwned(
	accepted urladmission.Accepted,
	request workerprotocol.Request,
	admittedAt time.Time,
	owner *attemptLock,
	write func(string, string, any) error,
	createMarker func(string) (bool, error),
) (attempt *Attempt, err error) {
	pendingPath := ""
	committed := false
	defer func() {
		if committed {
			if err != nil {
				err = &CommittedStageError{
					AttemptID: request.AttemptID,
					Err:       err,
				}
			}
			return
		}
		err = errors.Join(
			err,
			store.rollbackStage(
				pendingPath,
				removeStagedAttempt,
			),
		)
	}()
	pendingPath, path, err := store.prepareAttemptDirectories(
		request.AttemptID,
		createEvidenceDirectory,
	)
	if err != nil {
		return nil, err
	}
	admitted := admittedRecord(request, accepted.Frame, admittedAt)
	if err := write(path, admittedFile, admitted); err != nil {
		return nil, fmt.Errorf("stage attempt: %w", err)
	}
	committed, err = createMarker(request.AttemptID)
	if err != nil {
		return nil, err
	}
	if !committed {
		return nil, fmt.Errorf("%w: ownership marker was not created", ErrCorrupt)
	}
	attempt = &Attempt{
		store:       store,
		path:        path,
		pendingPath: pendingPath,
		admitted:    admitted,
		owner:       owner,
	}
	pendingPath = ""
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
		RequestFrame:  bytes.Clone(frame),
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
	if err := validateObservationEvidence(attempt.admitted, observation); err != nil {
		return fmt.Errorf("%w: observation evidence", ErrInvalid)
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
	return store.recoverWith(
		attemptID,
		reason,
		recoveryOperations{
			recoverable: store.recoverablePath,
			acquire:     store.acquireAttemptLock,
			marker:      store.hasOwnershipMarker,
			remove:      removeStagedAttempt,
			release:     func(owner *attemptLock) error { return owner.release() },
			owned:       store.recoverOwned,
		},
	)
}

func (store *Store) recoverWith(
	attemptID, reason string,
	operations recoveryOperations,
) error {
	if !validRecoveryReason(reason) {
		return fmt.Errorf("%w: recovery reason", ErrInvalid)
	}
	if _, _, err := operations.recoverable(attemptID); err != nil {
		return err
	}
	owner, err := operations.acquire(attemptID, false)
	if err != nil {
		if errors.Is(err, ErrCorrupt) || errors.Is(err, os.ErrNotExist) {
			return ErrCorrupt
		}
		return err
	}
	_, final, err := operations.recoverable(attemptID)
	if err != nil {
		return errors.Join(err, releaseError(operations.release(owner)))
	}
	marker, err := operations.marker(attemptID)
	if err != nil {
		return errors.Join(err, releaseError(operations.release(owner)))
	}
	if !marker {
		if final {
			return errors.Join(
				fmt.Errorf("%w: published attempt has no ownership marker",
					ErrCorrupt),
				releaseError(operations.release(owner)),
			)
		}
		removeErr := operations.remove(store.pendingPath(attemptID))
		return errors.Join(
			ErrUncommitted,
			removeErr,
			releaseError(operations.release(owner)),
		)
	}
	return operations.owned(attemptID, reason, owner)
}

func (store *Store) recoverOwned(
	attemptID,
	reason string,
	owner *attemptLock,
) (err error) {
	defer func() {
		err = publishResult(err, owner.release())
	}()
	return store.recoverOwnedStateWith(
		attemptID,
		reason,
		ownedRecoveryOperations{
			recoverable: store.recoverablePath,
			repair:      repairInterruptedRecords,
			published:   publicationExists,
			recover:     recoverPublished,
			terminal:    store.ensureTerminal,
			publish:     publishPendingDirectory,
			remove:      removePendingDirectory,
			marker:      publishMarker,
		},
	)
}

func (store *Store) recoverOwnedStateWith(
	attemptID, reason string,
	operations ownedRecoveryOperations,
) (err error) {
	path, final, err := operations.recoverable(attemptID)
	if err != nil {
		return err
	}
	if err := operations.repair(path); err != nil {
		return fmt.Errorf("repair interrupted records: %w", err)
	}
	if published, err := operations.published(path, attemptID); err != nil {
		return err
	} else if published {
		return operations.recover(path, attemptID)
	}
	if err := operations.terminal(path, attemptID, reason); err != nil {
		return err
	}
	if !final {
		pendingPath := store.pendingPath(attemptID)
		path, err = operations.publish(
			path,
			store.finalPath(attemptID),
			store.attemptsPath(),
		)
		if err != nil {
			return err
		}
		if err := operations.remove(pendingPath); err != nil {
			return err
		}
	} else if err := operations.remove(store.pendingPath(attemptID)); err != nil {
		return err
	}
	return operations.marker(path, attemptID)
}

func recoverPublished(path, attemptID string) error {
	return recoverPublishedWith(
		path,
		attemptID,
		inspectPublished,
		confirmPublication,
	)
}

func recoverPublishedWith(
	path, attemptID string,
	inspect func(string, string) (Records, error),
	confirm func(string) error,
) error {
	if _, err := inspect(path, attemptID); err != nil {
		return err
	}
	if err := confirm(path); err != nil {
		return fmt.Errorf("confirm recovered publication: %w", err)
	}
	return ErrDuplicate
}

func releaseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrRelease, err)
}

func publishResult(publicationErr, releaseErr error) error {
	var published error
	if publicationErr != nil {
		published = fmt.Errorf("%w: %w", ErrPublication, publicationErr)
	}
	if releaseErr == nil {
		return published
	}
	if publicationErr == nil {
		return fmt.Errorf("%w: %w", ErrRelease, releaseErr)
	}
	return errors.Join(
		published,
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

func (attempt *Attempt) publishDirectory() (string, error) {
	return attempt.publishDirectoryWith(pendingPublicationOperations{
		publish: publishPendingDirectory,
		remove:  removePendingDirectory,
	})
}

func (attempt *Attempt) publishDirectoryWith(
	operations pendingPublicationOperations,
) (string, error) {
	if attempt.pendingPath == "" {
		return attempt.path, nil
	}
	path, err := operations.publish(
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
	if err := operations.remove(pendingPath); err != nil {
		return "", err
	}
	return path, nil
}

func removePendingDirectory(path string) error {
	return removePendingDirectoryWith(
		path,
		pendingRemovalOperations{
			lstat:  os.Lstat,
			linked: pathIsLinked,
			secure: secureEvidenceTree,
			remove: os.Remove,
		},
	)
}

func removePendingDirectoryWith(
	path string,
	operations pendingRemovalOperations,
) error {
	info, err := operations.lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pending attempt: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		operations.linked(path, info) {
		return ErrCorrupt
	}
	if err := operations.secure(path); err != nil {
		return err
	}
	if err := operations.remove(path); err != nil {
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
	default:
		return ErrCorrupt
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
	return publishMarkerWith(
		path,
		attemptID,
		markerPublicationOperations{
			read:     readBundle,
			validate: validateBundleFiles,
			write:    writeRecord,
		},
	)
}

func publishMarkerWith(
	path, attemptID string,
	operations markerPublicationOperations,
) error {
	records, err := operations.read(path, attemptID)
	if err != nil {
		return fmt.Errorf("verify published bundle: %w", err)
	}
	if err := operations.validate(
		path,
		records.Receipt.TerminalFile,
		false,
	); err != nil {
		return fmt.Errorf("verify published bundle files: %w", err)
	}
	publication := Publication{
		Version:     Version,
		AttemptID:   attemptID,
		ReceiptHash: records.receiptHash,
	}
	if err := operations.write(path, publicationFile, publication); err != nil {
		return fmt.Errorf("write publication: %w", err)
	}
	return nil
}
