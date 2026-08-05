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

type operationTimings struct {
	Request      time.Duration
	Admission    time.Duration
	Staging      time.Duration
	Preparation  time.Duration
	ProcessStart time.Duration
	Input        time.Duration
	Worker       time.Duration
	Output       time.Duration
	Diagnostics  time.Duration
	Lifecycle    time.Duration
	Protocol     time.Duration
	Verification time.Duration
	Observation  time.Duration
	Publication  time.Duration
	Receipt      time.Duration
	Total        time.Duration
	Resources    supervision.Resources
	measured     phaseMask
}

type phaseMask uint32

const (
	phaseRequest phaseMask = 1 << iota
	phaseAdmission
	phaseStaging
	phasePreparation
	phaseProcessStart
	phaseInput
	phaseWorker
	phaseOutput
	phaseDiagnostics
	phaseLifecycle
	phaseProtocol
	phaseVerification
	phaseObservation
	phasePublication
	phaseReceipt
	phaseTotal
	allMeasuredPhases = 1<<iota - 1
)

type responseTimings struct {
	Protocol             time.Duration
	Verification         time.Duration
	Worker               time.Duration
	ProtocolMeasured     bool
	VerificationMeasured bool
	WorkerMeasured       bool
}

func (timings *operationTimings) absorb(
	process supervision.Outcome,
	response responseTimings,
) {
	timings.Preparation = process.Timings.Preparation
	timings.ProcessStart = process.Timings.Start
	timings.Input = process.Timings.Input
	timings.Worker = response.Worker
	timings.Output = process.Timings.Output
	timings.Diagnostics = process.Timings.Diagnostics
	timings.Lifecycle = process.Timings.Lifecycle
	timings.Resources = process.Resources
	timings.Protocol = response.Protocol
	timings.Verification = response.Verification
	if process.Timings.PreparationMeasured {
		timings.measured |= phasePreparation
	}
	if process.Timings.StartMeasured {
		timings.measured |= phaseProcessStart
	}
	if process.Timings.InputMeasured {
		timings.measured |= phaseInput
	}
	if process.Timings.OutputMeasured {
		timings.measured |= phaseOutput
	}
	if process.Timings.DiagnosticsMeasured {
		timings.measured |= phaseDiagnostics
	}
	if process.Timings.LifecycleMeasured {
		timings.measured |= phaseLifecycle
	}
	if response.ProtocolMeasured {
		timings.measured |= phaseProtocol
	}
	if response.VerificationMeasured {
		timings.measured |= phaseVerification
	}
	if response.WorkerMeasured {
		timings.measured |= phaseWorker
	}
}

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
	result, _ := operation.executeMeasured(ctx, input, mode)
	return result
}

func (operation *Operation) executeMeasured(
	ctx context.Context,
	input string,
	mode urlreference.Mode,
) (result Result, timings operationTimings) {
	started := time.Now()
	defer func() {
		timings.Total = time.Since(started)
		timings.measured |= phaseTotal
	}()
	if ctx == nil {
		return Result{
			Status: Rejected,
			Err: fmt.Errorf(
				"%w: nil execution context",
				urladmission.ErrRejected,
			),
		}, timings
	}
	admittedAt := time.Now().UTC()
	accepted, err := operation.admit(input, mode, admittedAt)
	timings.Request = accepted.Timings.Request
	timings.Admission = accepted.Timings.Admission
	if accepted.Timings.RequestMeasured {
		timings.measured |= phaseRequest
	}
	if accepted.Timings.AdmissionMeasured {
		timings.measured |= phaseAdmission
	}
	if err != nil {
		if errors.Is(err, urladmission.ErrRejected) {
			return Result{Status: Rejected, Err: err}, timings
		}
		return Result{Status: Failed, Err: errors.Join(ErrAdmission, err)}, timings
	}
	phaseStarted := time.Now()
	attempt, err := operation.stage(accepted, admittedAt)
	timings.Staging = time.Since(phaseStarted)
	timings.measured |= phaseStaging
	if err != nil {
		if committed, ok := errors.AsType[*attemptstore.CommittedStageError](err); ok &&
			committed.AttemptID == accepted.Request.AttemptID {
			return Result{
				AttemptID: committed.AttemptID,
				Status:    Indeterminate,
				Err:       errors.Join(ErrPersistence, err),
			}, timings
		}
		return Result{
			Status: Indeterminate,
			Err:    errors.Join(ErrPersistence, err),
		}, timings
	}
	result, process, responseTiming := operation.executeAcceptedMeasured(
		ctx,
		accepted,
		admittedAt,
	)
	timings.absorb(process, responseTiming)
	result.AttemptID = accepted.Request.AttemptID
	phaseStarted = time.Now()
	observation := observationFrom(result, process)
	timings.Observation = time.Since(phaseStarted)
	timings.measured |= phaseObservation
	if err := operation.publish(attempt, observation); err != nil {
		applyPublishError(&result, err)
	}
	publication := attempt.PublicationTimings()
	timings.Publication = publication.DurablePublication
	timings.Receipt = publication.Receipt
	if publication.DurablePublicationMeasured {
		timings.measured |= phasePublication
	}
	if publication.ReceiptMeasured {
		timings.measured |= phaseReceipt
	}
	return result, timings
}

func (operation *Operation) executeAccepted(
	ctx context.Context,
	accepted urladmission.Accepted,
	admittedAt time.Time,
) (Result, supervision.Outcome) {
	result, process, _ := operation.executeAcceptedMeasured(ctx, accepted, admittedAt)
	return result, process
}

func (operation *Operation) executeAcceptedMeasured(
	ctx context.Context,
	accepted urladmission.Accepted,
	admittedAt time.Time,
) (Result, supervision.Outcome, responseTimings) {
	var timings responseTimings
	startDeadline := admittedAt.Add(
		time.Duration(workerprotocol.StartTimeoutMS) * time.Millisecond,
	)
	process := operation.supervisor.RunBefore(ctx, accepted.Frame, startDeadline)
	if process.Status != supervision.Completed || !process.CleanupComplete {
		return Result{
			Status:  terminalStatus(process),
			Process: callerProcess(process),
			Err:     errors.Join(ErrProcess, process.Err),
		}, process, timings
	}

	started := time.Now()
	response, err := workerprotocol.DecodeResponseForRequestCorrelation(
		process.Stdout,
		accepted.Request,
		int(process.ExitCode),
	)
	timings.Protocol = time.Since(started)
	timings.ProtocolMeasured = true
	if err != nil {
		return Result{
			Status:  Failed,
			Process: callerProcess(process),
			Err:     errors.Join(ErrProtocol, err),
		}, process, timings
	}
	timings.Worker = time.Duration(response.DurationNS)
	timings.WorkerMeasured = true
	result, verification, measured := evaluateResponse(
		accepted,
		process,
		response,
	)
	timings.Verification = verification
	timings.VerificationMeasured = measured
	return result, process, timings
}
