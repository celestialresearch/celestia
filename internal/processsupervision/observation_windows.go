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

package processsupervision

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

func (supervisor *Supervisor) observe(
	ctx context.Context,
	process *launchedProcess,
	frame []byte,
	remaining time.Duration,
) Outcome {
	stdout := make(chan streamResult, 1)
	stderr := make(chan streamResult, 1)
	overflow := make(chan Status, 2)
	stdoutHandle := process.pipes.stdoutRead
	stderrHandle := process.pipes.stderrRead
	process.pipes.stdoutRead = 0
	process.pipes.stderrRead = 0
	stdoutReader := newStreamReader("output", stdoutHandle)
	stderrReader := newStreamReader("diagnostics", stderrHandle)
	go stdoutReader.read(supervisor.limits.OutputBytes, OutputOverflow, stdout, overflow)
	go stderrReader.read(supervisor.limits.ErrorBytes, ErrorOverflow, stderr, overflow)
	input := make(chan inputResult, 1)
	inputDone := make(chan inputResult, 1)
	stdinHandle := process.pipes.stdinWrite
	process.pipes.stdinWrite = 0
	inputWriter := newInputWriter(stdinHandle)
	go func() {
		result := inputWriter.write(frame)
		input <- result
		inputDone <- result
	}()
	if remaining <= 0 {
		remaining = time.Nanosecond
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	status, cause := awaitProcess(
		ctx,
		timer.C,
		poll.C,
		func() (bool, error) {
			return processComplete(process.info.Process)
		},
		overflow,
		input,
	)
	cleanupDeadline := time.Now().Add(supervisor.limits.CleanupTimeout)
	joinDeadline := cleanupDeadline.Add(100 * time.Millisecond)
	if status != Completed {
		if err := windows.TerminateJobObject(process.job, 1); err != nil {
			status = CleanupFailed
			cause = errors.Join(cause, fmt.Errorf("terminate job: %w", err))
		}
	}
	cleanupComplete, waitErr := waitCleanup(
		process.info.Process,
		process.job,
		cleanupRemaining(cleanupDeadline),
	)
	if !cleanupComplete {
		status = CleanupFailed
		cause = errors.Join(cause, waitErr)
	}
	inputResult := awaitInput(inputWriter, inputDone, cleanupDeadline, joinDeadline)
	status, cause, cleanupComplete = applyInputResult(
		status,
		cause,
		cleanupComplete,
		inputResult,
	)
	out := awaitStream(stdoutReader, stdout, cleanupDeadline, joinDeadline)
	diagnostics := awaitStream(stderrReader, stderr, cleanupDeadline, joinDeadline)
	outcome := finishOutcome(process, status, cause, cleanupComplete, out, diagnostics)
	if err := process.close(); err != nil {
		outcome.Status = CleanupFailed
		outcome.CleanupComplete = false
		outcome.Err = errors.Join(outcome.Err, err)
	}
	return outcome
}

func cleanupRemaining(deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}

func awaitProcess(
	ctx context.Context,
	timeout <-chan time.Time,
	poll <-chan time.Time,
	complete func() (bool, error),
	overflow <-chan Status,
	input <-chan inputResult,
) (Status, error) {
	for {
		if status, cause, ready := readProcessResult(complete); ready {
			return status, cause
		}
		if timeoutReady(timeout) {
			return resolveProcessBoundary(complete, TimedOut, context.DeadlineExceeded)
		}
		select {
		case <-poll:
			continue
		case <-ctx.Done():
			return resolveProcessBoundary(complete, Cancelled, ctx.Err())
		case <-timeout:
			return resolveProcessBoundary(complete, TimedOut, context.DeadlineExceeded)
		case status := <-overflow:
			return status, errStreamLimit
		case result := <-input:
			if result.cleanupErr != nil {
				return CleanupFailed, errors.Join(result.err, result.cleanupErr)
			}
			if result.err != nil {
				return ExitFailed, result.err
			}
			input = nil
		}
	}
}

func processComplete(process windows.Handle) (bool, error) {
	event, err := windows.WaitForSingleObject(process, 0)
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

func finishOutcome(
	process *launchedProcess,
	status Status,
	cause error,
	cleanupComplete bool,
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
		Duration:        time.Since(process.started),
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
		status = CleanupFailed
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
		return CleanupFailed,
			errors.Join(cause, result.err, result.cleanupErr),
			false
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
