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
	"errors"
	"fmt"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/attempt"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

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

func observationFrom(
	result Result,
	process supervision.Outcome,
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
	if result.Process.Status == supervision.Completed &&
		errors.Is(result.Err, ErrProtocol) {
		return protocolRejected
	}
	return protocolNotRun
}

func observationProcessStatus(result Result) string {
	if result.Response != nil &&
		result.Response.Status == workerprotocol.Failed {
		return string(supervision.ExitFailed)
	}
	return string(result.Process.Status)
}

func observationProcessError(
	result Result,
	process supervision.Outcome,
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
	if process.Status != supervision.Completed {
		return result.Err.Error()
	}
	return ""
}
