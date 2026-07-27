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

	"celestia.research/governed-operation/internal/attemptstore"
	"celestia.research/governed-operation/internal/processsupervision"
	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/urlreference"
	"celestia.research/governed-operation/internal/workerprotocol"
)

type Operation struct {
	supervisor *processsupervision.Supervisor
	store      *attemptstore.Store
	admit      func(string, urlreference.Mode, time.Time) (urladmission.Accepted, error)
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
	supervisor, err := processsupervision.New(workerPath, operationLimits())
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
	attempt, err := operation.store.Stage(accepted, admittedAt)
	if err != nil {
		return Result{
			Status: Indeterminate,
			Err:    errors.Join(ErrPersistence, err),
		}
	}
	result, process := operation.executeAccepted(ctx, accepted, admittedAt)
	result.AttemptID = accepted.Request.AttemptID
	observation := observationFrom(result, process)
	if err := attempt.Publish(observation); err != nil {
		applyPublishError(&result, err)
	}
	return result
}

func applyPublishError(result *Result, err error) {
	if errors.Is(err, attemptstore.ErrPublication) {
		result.Status = Indeterminate
		result.Err = errors.Join(result.Err, ErrPersistence, err)
		if errors.Is(err, attemptstore.ErrRelease) {
			result.Err = errors.Join(result.Err, ErrCleanup)
		}
		return
	}
	if errors.Is(err, attemptstore.ErrRelease) {
		result.Err = errors.Join(result.Err, ErrCleanup, err)
		return
	}
	result.Status = Indeterminate
	result.Err = errors.Join(result.Err, ErrPersistence, err)
}

func (operation *Operation) executeAccepted(
	ctx context.Context,
	accepted urladmission.Accepted,
	admittedAt time.Time,
) (Result, processsupervision.Outcome) {
	startDeadline, err := admittedStartDeadline(ctx, accepted.Request.Deadline)
	if err != nil {
		return Result{
			Status: Failed,
			Err:    errors.Join(ErrProtocol, err),
		}, processsupervision.Outcome{}
	}
	process := operation.supervisor.RunBefore(ctx, accepted.Frame, startDeadline)
	if process.Status != processsupervision.Completed || !process.CleanupComplete {
		return Result{
			Status:  terminalStatus(process),
			Process: callerProcess(process),
			Err:     errors.Join(ErrProcess, process.Err),
		}, process
	}

	_, correlation, err := workerprotocol.DecodeRequest(accepted.Frame, admittedAt)
	if err != nil {
		return Result{
			Status:  Failed,
			Process: callerProcess(process),
			Err:     errors.Join(ErrProtocol, err),
		}, process
	}
	response, err := workerprotocol.DecodeResponse(
		process.Stdout,
		correlation,
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

func evaluateResponse(
	accepted urladmission.Accepted,
	process processsupervision.Outcome,
	response workerprotocol.Response,
) Result {
	diagnostics := projectDiagnostics(response.Status, response.Diagnostics)
	response.Diagnostics = nil
	if response.Status != workerprotocol.Completed {
		return Result{
			Status:      Failed,
			Process:     callerProcess(process),
			Response:    &response,
			Diagnostics: diagnostics,
			Err: errors.Join(
				ErrProcess,
				fmt.Errorf("worker status %s", response.Status),
			),
		}
	}
	result := Result{
		Status:      ExecutedUnverified,
		Process:     callerProcess(process),
		Response:    &response,
		Diagnostics: diagnostics,
		Verification: Verification{
			VerifierID:      VerifierID,
			VerifierVersion: VerifierVersion,
		},
	}
	if response.Output == nil {
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

func callerProcess(process processsupervision.Outcome) processsupervision.Outcome {
	process.Stdout = nil
	process.Stderr = nil
	return process
}

func projectDiagnostics(
	status workerprotocol.Status,
	values []workerprotocol.Diagnostic,
) []Diagnostic {
	if status == workerprotocol.Completed || len(values) == 0 {
		return nil
	}
	diagnostics := make([]Diagnostic, len(values))
	for index, value := range values {
		code := diagnosticCode(status, value.Code)
		diagnostics[index] = Diagnostic{
			Code:    code,
			Message: diagnosticMessage(code),
		}
	}
	return diagnostics
}

func diagnosticCode(status workerprotocol.Status, code string) string {
	if status == workerprotocol.Rejected && code == "invalid_reference" {
		return code
	}
	return "worker_failure"
}

func diagnosticMessage(code string) string {
	switch code {
	case "invalid_reference":
		return "The worker rejected the URL reference"
	default:
		return "The worker reported a failure"
	}
}

func admittedStartDeadline(
	parent context.Context,
	deadlineValue string,
) (time.Time, error) {
	if parent == nil {
		return time.Time{}, errors.New("nil execution context")
	}
	deadline, err := time.Parse(time.RFC3339Nano, deadlineValue)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse admitted deadline: %w", err)
	}
	return deadline, nil
}

func terminalStatus(process processsupervision.Outcome) Status {
	switch process.Status {
	case processsupervision.Cancelled:
		if errors.Is(process.Err, context.DeadlineExceeded) {
			return TimedOut
		}
		return Cancelled
	case processsupervision.TimedOut:
		return TimedOut
	case processsupervision.StartFailed:
		if errors.Is(process.Err, context.DeadlineExceeded) {
			return TimedOut
		}
		return Failed
	case processsupervision.Completed,
		processsupervision.OutputOverflow,
		processsupervision.ErrorOverflow,
		processsupervision.ExitFailed,
		processsupervision.CleanupFailed:
		return Failed
	}
	return Failed
}

func operationLimits() processsupervision.Limits {
	return processsupervision.Limits{
		InputBytes:     workerprotocol.MaxResponseBytes,
		OutputBytes:    workerprotocol.MaxResponseBytes,
		ErrorBytes:     workerprotocol.StderrBytes,
		MemoryBytes:    workerprotocol.MemoryBytes,
		Processes:      workerprotocol.Processes,
		StartupTimeout: containmentStartupTimeout,
		Timeout:        time.Duration(workerprotocol.TimeoutMS) * time.Millisecond,
		CleanupTimeout: time.Second,
	}
}

func observationFrom(
	result Result,
	process processsupervision.Outcome,
) attemptstore.Observation {
	processStatus := observationProcessStatus(result)
	return attemptstore.Observation{
		Version:          attemptstore.Version,
		AttemptID:        result.AttemptID,
		WorkerSHA256:     fmt.Sprintf("%x", process.WorkerSHA256),
		ProcessStatus:    processStatus,
		ProcessError:     observationProcessError(result, process),
		ExitCode:         process.ExitCode,
		Stdout:           process.Stdout,
		Stderr:           process.Stderr,
		CleanupComplete:  process.CleanupComplete,
		ProtocolStatus:   observationProtocolStatus(result),
		VerificationID:   result.Verification.VerifierID,
		VerificationVer:  result.Verification.VerifierVersion,
		ExpectedOutput:   result.Verification.Expected,
		VerificationPass: result.Verification.Matched,
		TerminalStatus:   string(result.Status),
		DurationNS:       process.Duration.Nanoseconds(),
	}
}

func observationProtocolStatus(result Result) string {
	if result.Response != nil {
		return protocolValid
	}
	if result.Process.Status == processsupervision.Completed &&
		errors.Is(result.Err, ErrProtocol) {
		return protocolRejected
	}
	return protocolNotRun
}

func observationProcessStatus(result Result) string {
	if result.Response != nil &&
		result.Response.Status == workerprotocol.Failed {
		return string(processsupervision.ExitFailed)
	}
	return string(result.Process.Status)
}

func observationProcessError(
	result Result,
	process processsupervision.Outcome,
) string {
	if process.Err != nil {
		return process.Err.Error()
	}
	if result.Err == nil {
		return ""
	}
	if result.Response != nil &&
		result.Response.Status == workerprotocol.Failed {
		return result.Err.Error()
	}
	if process.Status != processsupervision.Completed {
		return result.Err.Error()
	}
	return ""
}
