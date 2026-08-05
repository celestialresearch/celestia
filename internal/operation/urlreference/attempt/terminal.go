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
	"time"
)

type markerPublicationOperations struct {
	read     func(string, string) (Records, error)
	validate func(string, string, bool) error
	write    func(string, string, any) error
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

func writeOrMatchReceipt(path, attemptID, kind, terminalFile, state string) error {
	_, err := writeOrMatchReceiptMeasured(path, attemptID, kind, terminalFile, state)
	return err
}

func writeOrMatchReceiptMeasured(
	path, attemptID, kind, terminalFile, state string,
) (time.Duration, error) {
	started := time.Now()
	admittedHash, err := fileHash(path, admittedFile)
	if err != nil {
		return time.Since(started), err
	}
	terminalHash, err := fileHash(path, terminalFile)
	if err != nil {
		return time.Since(started), err
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
	err = writeOrMatchRecord(path, receiptFile, receipt)
	return time.Since(started), err
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
