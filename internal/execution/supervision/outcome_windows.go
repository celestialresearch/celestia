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

package supervision

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"time"
)

func finishOutcome(
	process *launchedProcess,
	status Status,
	cause error,
	cleanupComplete bool,
	duration time.Duration,
	out streamResult,
	diagnostics streamResult,
) Outcome {
	status, cause, cleanupComplete = applyStreamResult(
		status,
		cause,
		cleanupComplete,
		out,
		"output",
		OutputOverflow,
	)
	status, cause, cleanupComplete = applyStreamResult(
		status,
		cause,
		cleanupComplete,
		diagnostics,
		"diagnostics",
		ErrorOverflow,
	)
	status, exitCode, cause := readExit(process.info.Process, status, cause)
	return Outcome{
		Status:          status,
		Stdout:          out.data,
		Stderr:          diagnostics.data,
		ExitCode:        exitCode,
		Duration:        duration,
		CleanupComplete: cleanupComplete,
		Err:             cause,
	}
}

func applyStreamResult(
	status Status,
	cause error,
	cleanupComplete bool,
	result streamResult,
	name string,
	overflowStatus Status,
) (Status, error, bool) {
	if result.cleanupErr != nil {
		cause = errors.Join(
			cause,
			fmt.Errorf("clean up worker %s: %w", name, result.cleanupErr),
		)
		cleanupComplete = false
	}
	if errors.Is(result.err, errStreamLimit) && status == Completed {
		status = overflowStatus
	}
	if errors.Is(result.err, errStreamLimit) {
		return status, errors.Join(cause, result.err), cleanupComplete
	}
	if result.err != nil {
		if status == Completed {
			status = ExitFailed
		}
		cause = errors.Join(cause, fmt.Errorf("read worker %s: %w", name, result.err))
	}
	return status, cause, cleanupComplete
}

func applyInputResult(
	status Status,
	cause error,
	cleanupComplete bool,
	result inputResult,
) (Status, error, bool) {
	if result.cleanupErr != nil {
		return status,
			errors.Join(cause, result.err, result.cleanupErr, result.joinErr),
			false
	}
	if result.joinErr != nil {
		return status, errors.Join(cause, result.err, result.joinErr), false
	}
	if result.err != nil {
		if status == Completed {
			status = ExitFailed
		}
		cause = errors.Join(cause, result.err)
	}
	return status, cause, cleanupComplete
}

func readExit(process windows.Handle, status Status, cause error) (Status, uint32, error) {
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process, &exitCode); err != nil {
		if status == Completed {
			status = ExitFailed
		}
		cause = errors.Join(cause, fmt.Errorf("read exit code: %w", err))
	} else if status == Completed && !protocolExit(exitCode) {
		status = ExitFailed
	}
	return status, exitCode, cause
}

func protocolExit(exitCode uint32) bool {
	switch exitCode {
	case 0, 2, 3:
		return true
	default:
		return false
	}
}
