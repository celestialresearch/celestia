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
	"fmt"
	"os"
	"path/filepath"
)

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
