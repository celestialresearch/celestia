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
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

func awaitProcessWithInput(
	ctx context.Context,
	timeout <-chan time.Time,
	poll <-chan time.Time,
	complete func() (bool, error),
	overflow <-chan Status,
	input <-chan inputResult,
) (Status, error, bool) {
	inputApplied := false
	for {
		if status, cause, ready := readProcessBoundary(ctx, timeout, complete); ready {
			return status, cause, inputApplied
		}
		select {
		case <-poll:
			continue
		case <-ctx.Done():
			status, cause := resolveProcessBoundary(complete, Cancelled, ctx.Err())
			return status, cause, inputApplied
		case <-timeout:
			status, cause := resolveProcessBoundary(
				complete, TimedOut, context.DeadlineExceeded,
			)
			return status, cause, inputApplied
		case status := <-overflow:
			if boundaryStatus, cause, ready := readProcessBoundary(ctx, timeout, complete); ready {
				return boundaryStatus, cause, inputApplied
			}
			return status, errStreamLimit, inputApplied
		case result := <-input:
			if status, cause, ready := readProcessBoundary(ctx, timeout, complete); ready {
				return status, cause, inputApplied
			}
			inputApplied = true
			if result.cleanupErr != nil {
				return CleanupFailed,
					errors.Join(result.err, result.cleanupErr),
					inputApplied
			}
			if result.err != nil {
				return ExitFailed, result.err, inputApplied
			}
			input = nil
		}
	}
}

func readProcessBoundary(
	ctx context.Context,
	timeout <-chan time.Time,
	complete func() (bool, error),
) (Status, error, bool) {
	if status, cause, ready := readProcessResult(complete); ready {
		return status, cause, true
	}
	if timeoutReady(timeout) {
		status, cause := resolveProcessBoundary(
			complete,
			TimedOut,
			context.DeadlineExceeded,
		)
		return status, cause, true
	}
	if cause := ctx.Err(); cause != nil {
		status, cause := resolveProcessBoundary(complete, Cancelled, cause)
		return status, cause, true
	}
	return Status(""), nil, false
}

func processComplete(process windows.Handle) (bool, error) {
	return processCompleteWith(process, windows.WaitForSingleObject)
}

func processCompleteWith(
	process windows.Handle,
	wait func(windows.Handle, uint32) (uint32, error),
) (bool, error) {
	event, err := wait(process, 0)
	if err != nil {
		return false, fmt.Errorf("wait for worker: %w", err)
	}
	switch event {
	case uint32(windows.WAIT_OBJECT_0):
		return true, nil
	case uint32(windows.WAIT_TIMEOUT):
		return false, nil
	default:
		return false, fmt.Errorf("unexpected worker wait result: %d", event)
	}
}

func timeoutReady(timeout <-chan time.Time) bool {
	select {
	case <-timeout:
		return true
	default:
		return false
	}
}

func readProcessResult(complete func() (bool, error)) (Status, error, bool) {
	done, err := complete()
	if err != nil {
		return ExitFailed, err, true
	}
	if done {
		return Completed, nil, true
	}
	return Status(""), nil, false
}

func resolveProcessBoundary(
	complete func() (bool, error),
	status Status,
	cause error,
) (Status, error) {
	if waitStatus, waitErr, ready := readProcessResult(complete); ready {
		return waitStatus, waitErr
	}
	return status, cause
}
