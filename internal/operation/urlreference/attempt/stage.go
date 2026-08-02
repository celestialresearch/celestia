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
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"errors"
	"fmt"
	"sync"
	"time"
)

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
