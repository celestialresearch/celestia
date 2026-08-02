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
