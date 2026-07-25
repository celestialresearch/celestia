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

package urloperation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"celestia.research/governed-operation/internal/attemptstore"
	"celestia.research/governed-operation/internal/processsupervision"
	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/urlreference"
	"celestia.research/governed-operation/internal/workerprotocol"
)

const (
	VerifierID      = "go-url-reference"
	VerifierVersion = "0"
)

var (
	ErrProcess      = errors.New("worker process failed")
	ErrProtocol     = errors.New("worker protocol failed")
	ErrVerification = errors.New("worker output failed verification")
	ErrPersistence  = errors.New("attempt persistence failed")
)

type Status string

const (
	Failed             Status = "failed"
	Rejected           Status = "rejected"
	ExecutedUnverified Status = "executed_unverified"
	Verified           Status = "verified"
	Indeterminate      Status = "indeterminate"
)

type Verification struct {
	VerifierID      string
	VerifierVersion string
	Expected        string
	Matched         bool
}

type Result struct {
	Status       Status
	Process      processsupervision.Outcome
	Response     *workerprotocol.Response
	Verification Verification
	AttemptID    string
	Err          error
}

type Operation struct {
	supervisor *processsupervision.Supervisor
	store      *attemptstore.Store
}

func New(
	workerPath string,
	limits processsupervision.Limits,
	evidenceRoot string,
) (*Operation, error) {
	supervisor, err := processsupervision.New(workerPath, limits)
	if err != nil {
		return nil, fmt.Errorf("configure URL operation: %w", err)
	}
	store, err := attemptstore.New(evidenceRoot)
	if err != nil {
		return nil, fmt.Errorf("configure URL operation evidence: %w", err)
	}
	return &Operation{supervisor: supervisor, store: store}, nil
}

func (operation *Operation) Execute(
	ctx context.Context,
	input string,
	mode urlreference.Mode,
) Result {
	admittedAt := time.Now().UTC()
	accepted, err := urladmission.Admit(input, mode, admittedAt)
	if err != nil {
		return Result{Status: Rejected, Err: err}
	}
	attempt, err := operation.store.Stage(accepted, admittedAt)
	if err != nil {
		return Result{
			Status:    Indeterminate,
			AttemptID: accepted.Request.AttemptID,
			Err:       errors.Join(ErrPersistence, err),
		}
	}
	result := operation.executeAccepted(ctx, accepted, admittedAt)
	result.AttemptID = accepted.Request.AttemptID
	observation := observationFrom(result)
	if err := attempt.Publish(observation); err != nil {
		result.Status = Indeterminate
		result.Err = errors.Join(result.Err, ErrPersistence, err)
	}
	return result
}

func (operation *Operation) executeAccepted(
	ctx context.Context,
	accepted urladmission.Accepted,
	admittedAt time.Time,
) Result {
	process := operation.supervisor.Run(ctx, accepted.Frame)
	if process.Status != processsupervision.Completed {
		return Result{
			Status:  Failed,
			Process: process,
			Err:     errors.Join(ErrProcess, process.Err),
		}
	}

	_, correlation, err := workerprotocol.DecodeRequest(accepted.Frame, admittedAt)
	if err != nil {
		return Result{
			Status:  Failed,
			Process: process,
			Err:     errors.Join(ErrProtocol, err),
		}
	}
	response, err := workerprotocol.DecodeResponse(
		process.Stdout,
		correlation,
		int(process.ExitCode),
	)
	if err != nil {
		return Result{
			Status:  Failed,
			Process: process,
			Err:     errors.Join(ErrProtocol, err),
		}
	}
	result := Result{
		Status:   ExecutedUnverified,
		Process:  process,
		Response: &response,
		Verification: Verification{
			VerifierID:      VerifierID,
			VerifierVersion: VerifierVersion,
		},
	}
	if response.Status != workerprotocol.Completed || response.Output == nil {
		result.Err = ErrVerification
		return result
	}
	expected, err := urlreference.Transform(
		accepted.Request.Input,
		urlreference.Mode(accepted.Request.Mode),
	)
	if err != nil {
		result.Err = errors.Join(ErrVerification, err)
		return result
	}
	result.Verification.Expected = expected
	result.Verification.Matched = *response.Output == expected
	if !result.Verification.Matched {
		result.Err = ErrVerification
		return result
	}
	result.Status = Verified
	return result
}

func observationFrom(result Result) attemptstore.Observation {
	protocolStatus := "not_checked"
	if result.Response != nil {
		protocolStatus = "valid"
	} else if errors.Is(result.Err, ErrProtocol) {
		protocolStatus = "invalid"
	}
	processError := ""
	if result.Process.Err != nil {
		processError = result.Process.Err.Error()
	}
	return attemptstore.Observation{
		Version:          attemptstore.Version,
		AttemptID:        result.AttemptID,
		WorkerSHA256:     fmt.Sprintf("%x", result.Process.WorkerSHA256),
		ProcessStatus:    string(result.Process.Status),
		ProcessError:     processError,
		ExitCode:         result.Process.ExitCode,
		Stdout:           result.Process.Stdout,
		Stderr:           result.Process.Stderr,
		CleanupComplete:  result.Process.CleanupComplete,
		ProtocolStatus:   protocolStatus,
		VerificationID:   result.Verification.VerifierID,
		VerificationVer:  result.Verification.VerifierVersion,
		ExpectedOutput:   result.Verification.Expected,
		VerificationPass: result.Verification.Matched,
		TerminalStatus:   string(result.Status),
		DurationNS:       result.Process.Duration.Nanoseconds(),
	}
}
