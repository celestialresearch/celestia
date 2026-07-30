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
	go inputWriter.publish(frame, input, inputDone)
	remaining = executionAllowance(remaining)
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	status, cause, inputApplied := awaitProcessWithInput(
		ctx,
		timer.C,
		poll.C,
		func() (bool, error) {
			return processComplete(process.info.Process)
		},
		overflow,
		input,
	)
	executionDuration := time.Since(process.started)
	cleanupDeadline := time.Now().Add(supervisor.limits.CleanupTimeout)
	joinDeadline := cleanupDeadline.Add(100 * time.Millisecond)
	cleanupComplete, cause := cleanupProcess(process, status, cause, cleanupDeadline)
	inputResult := awaitInput(inputWriter, inputDone, cleanupDeadline, joinDeadline)
	inputResult = unappliedInputResult(inputResult, inputApplied)
	status, cause, cleanupComplete = applyInputResult(
		status,
		cause,
		cleanupComplete,
		inputResult,
	)
	out := awaitStream(stdoutReader, stdout, cleanupDeadline, joinDeadline)
	diagnostics := awaitStream(stderrReader, stderr, cleanupDeadline, joinDeadline)
	outcome := finishOutcome(process, status, cause, cleanupComplete, executionDuration, out, diagnostics)
	closeComplete, closeErr := finaliseCleanup(cleanupDeadline, process.close)
	return applyFinalCleanup(outcome, closeComplete, closeErr)
}

func unappliedInputResult(result inputResult, applied bool) inputResult {
	if applied {
		result.err = nil
		result.cleanupErr = nil
	}
	return result
}

func executionAllowance(remaining time.Duration) time.Duration {
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}

func applyFinalCleanup(outcome Outcome, complete bool, err error) Outcome {
	if complete {
		return outcome
	}
	outcome.CleanupComplete = false
	outcome.Err = errors.Join(outcome.Err, err)
	return outcome
}

func cleanupProcess(
	process *launchedProcess,
	status Status,
	cause error,
	deadline time.Time,
) (bool, error) {
	return cleanupProcessWith(
		status,
		cause,
		deadline,
		func() (bool, error) {
			return jobEmpty(process.job)
		},
		func() error {
			return windows.TerminateJobObject(process.job, 1)
		},
		func(timeout time.Duration) (bool, error) {
			return waitCleanup(process.info.Process, process.job, timeout)
		},
	)
}

func cleanupProcessWith(
	status Status,
	cause error,
	deadline time.Time,
	treeEmpty func() (bool, error),
	terminate func() error,
	wait func(time.Duration) (bool, error),
) (bool, error) {
	cleanupComplete := true
	empty, treeErr := treeEmpty()
	if treeErr != nil {
		cleanupComplete = false
		cause = errors.Join(cause, treeErr)
	}
	if status != Completed || !empty {
		var terminateComplete bool
		cause, terminateComplete = terminateForCleanup(cause, terminate)
		if !terminateComplete {
			cleanupComplete = false
		}
	}
	waitComplete, waitErr := wait(cleanupRemaining(deadline))
	if !waitComplete {
		cleanupComplete = false
		cause = errors.Join(cause, waitErr)
	}
	return cleanupComplete, cause
}

func terminateForCleanup(cause error, terminate func() error) (error, bool) {
	if err := terminate(); err != nil {
		return errors.Join(cause, fmt.Errorf("terminate job: %w", err)), false
	}
	return cause, true
}

func finaliseCleanup(deadline time.Time, closeResources func() error) (bool, error) {
	overdue := !time.Now().Before(deadline)
	err := closeResources()
	if overdue || !time.Now().Before(deadline) {
		err = errors.Join(err, errors.New("final cleanup deadline exceeded"))
	}
	return err == nil, err
}

func cleanupRemaining(deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
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
	status, cause, _ := awaitProcessWithInput(
		ctx, timeout, poll, complete, overflow, input,
	)
	return status, cause
}

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
