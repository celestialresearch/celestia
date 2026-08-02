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

//go:build windows && amd64

package urloperation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/attempt"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
)

type Operation struct {
	supervisor *supervision.Supervisor
	store      *attemptstore.Store
	admit      func(string, urlreference.Mode, time.Time) (urladmission.Accepted, error)
	stage      func(
		urladmission.Accepted,
		time.Time,
	) (*attemptstore.Attempt, error)
	publish func(*attemptstore.Attempt, attemptstore.Observation) error
}

const (
	protocolNotRun            = "not_run"
	protocolValid             = "valid"
	protocolRejected          = "rejected"
	containmentStartupTimeout = 10 * time.Second
)

func New(
	workerPath string,
	evidenceRoot string,
) (*Operation, error) {
	supervisor, err := supervision.New(workerPath, operationLimits())
	if err != nil {
		return nil, fmt.Errorf("configure URL operation: %w", err)
	}
	store, err := attemptstore.New(evidenceRoot)
	if err != nil {
		return nil, fmt.Errorf("configure URL operation evidence: %w", err)
	}
	return &Operation{
		supervisor: supervisor,
		store:      store,
		admit:      urladmission.Admit,
		stage:      store.Stage,
		publish: func(
			attempt *attemptstore.Attempt,
			observation attemptstore.Observation,
		) error {
			return attempt.Publish(observation)
		},
	}, nil
}

func (operation *Operation) Execute(
	ctx context.Context,
	input string,
	mode urlreference.Mode,
) Result {
	if ctx == nil {
		return Result{
			Status: Rejected,
			Err: fmt.Errorf(
				"%w: nil execution context",
				urladmission.ErrRejected,
			),
		}
	}
	admittedAt := time.Now().UTC()
	accepted, err := operation.admit(input, mode, admittedAt)
	if err != nil {
		if errors.Is(err, urladmission.ErrRejected) {
			return Result{Status: Rejected, Err: err}
		}
		return Result{Status: Failed, Err: errors.Join(ErrAdmission, err)}
	}
	attempt, err := operation.stage(accepted, admittedAt)
	if err != nil {
		if committed, ok := errors.AsType[*attemptstore.CommittedStageError](err); ok &&
			committed.AttemptID == accepted.Request.AttemptID {
			return Result{
				AttemptID: committed.AttemptID,
				Status:    Indeterminate,
				Err:       errors.Join(ErrPersistence, err),
			}
		}
		return Result{
			Status: Indeterminate,
			Err:    errors.Join(ErrPersistence, err),
		}
	}
	result, process := operation.executeAccepted(ctx, accepted, admittedAt)
	result.AttemptID = accepted.Request.AttemptID
	observation := observationFrom(result, process)
	if err := operation.publish(attempt, observation); err != nil {
		applyPublishError(&result, err)
	}
	return result
}

func (operation *Operation) executeAccepted(
	ctx context.Context,
	accepted urladmission.Accepted,
	admittedAt time.Time,
) (Result, supervision.Outcome) {
	startDeadline := admittedAt.Add(
		time.Duration(workerprotocol.StartTimeoutMS) * time.Millisecond,
	)
	process := operation.supervisor.RunBefore(ctx, accepted.Frame, startDeadline)
	if process.Status != supervision.Completed || !process.CleanupComplete {
		return Result{
			Status:  terminalStatus(process),
			Process: callerProcess(process),
			Err:     errors.Join(ErrProcess, process.Err),
		}, process
	}

	response, err := workerprotocol.DecodeResponseForRequestCorrelation(
		process.Stdout,
		accepted.Request,
		int(process.ExitCode),
	)
	if err != nil {
		return Result{
			Status:  Failed,
			Process: callerProcess(process),
			Err:     errors.Join(ErrProtocol, err),
		}, process
	}
	return evaluateResponse(accepted, process, response), process
}
