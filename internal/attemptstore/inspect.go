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
)

func (store *Store) Inspect(attemptID string) (records Records, err error) {
	return store.inspectWithLock(attemptID, store.acquireAttemptLock)
}

func (store *Store) inspectWithLock(
	attemptID string,
	acquire func(string, bool) (*attemptLock, error),
) (records Records, err error) {
	path, err := store.attemptPath(attemptID)
	if err != nil {
		return Records{}, err
	}
	current, err := store.hasOwnershipMarker(attemptID)
	if err != nil {
		return Records{}, err
	}
	if !current {
		return Records{}, fmt.Errorf("%w: attempt %s has no ownership marker", ErrCorrupt, attemptID)
	}
	if err := store.validateAttemptLock(attemptID); err != nil {
		return Records{}, err
	}
	published, err := publicationExists(path, attemptID)
	if err == nil && published {
		return store.inspectPublishedPath(path, attemptID)
	}
	owner, err := acquire(attemptID, false)
	if err != nil {
		return Records{}, err
	}
	defer func() {
		if releaseErr := owner.release(); releaseErr != nil {
			records = Records{}
			err = errors.Join(err, releaseError(releaseErr))
		}
	}()
	return store.inspectPublishedPath(path, attemptID)
}

func (store *Store) inspectPublishedPath(path, attemptID string) (Records, error) {
	if err := confirmPublication(store.attemptsPath()); err != nil {
		return Records{}, fmt.Errorf("confirm attempt publication: %w", err)
	}
	if err := confirmPublication(path); err != nil {
		return Records{}, fmt.Errorf("confirm evidence publication: %w", err)
	}
	return inspectPublished(path, attemptID)
}

func inspectPublished(path, attemptID string) (Records, error) {
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
	if err := validateBundleFiles(path, records.Receipt.TerminalFile, true); err != nil {
		return Records{}, err
	}
	return records, nil
}

func validateBundleFiles(path, terminalFile string, published bool) (err error) {
	return validateBundleFilesWith(
		path,
		terminalFile,
		published,
		func(root *os.Root) (*os.File, error) {
			return root.Open(".")
		},
		func(directory *os.File) ([]os.DirEntry, error) {
			return directory.ReadDir(-1)
		},
	)
}

func validateBundleFilesWith(
	path string,
	terminalFile string,
	published bool,
	openDirectory func(*os.Root) (*os.File, error),
	readDirectory func(*os.File) ([]os.DirEntry, error),
) (err error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return fmt.Errorf("open evidence bundle: %w", err)
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	directory, err := openDirectory(root)
	if err != nil {
		return fmt.Errorf("open evidence directory: %w", err)
	}
	defer func() {
		err = errors.Join(err, directory.Close())
	}()
	entries, err := readDirectory(directory)
	if err != nil {
		return fmt.Errorf("read evidence directory: %w", err)
	}
	expected := map[string]bool{
		admittedFile: true,
		terminalFile: true,
		receiptFile:  true,
	}
	if published {
		expected[publicationFile] = true
	}
	if len(entries) != len(expected) {
		return ErrCorrupt
	}
	for _, entry := range entries {
		if !expected[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrCorrupt
		}
	}
	return nil
}

func readBundle(path, attemptID string) (Records, error) {
	var records Records
	if err := readRecord(path, admittedFile, &records.Admitted); err != nil {
		return Records{}, err
	}
	receiptHash, err := readRecordHash(path, receiptFile, &records.Receipt)
	if err != nil {
		return Records{}, err
	}
	records.receiptHash = receiptHash
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
	if records.Observation != nil &&
		validateRetainedObservationEvidence(records.Admitted, *records.Observation) != nil {
		return Records{}, ErrCorrupt
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
