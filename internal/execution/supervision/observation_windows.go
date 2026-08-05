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
	"time"
)

func (supervisor *Supervisor) observe(
	ctx context.Context,
	process *launchedProcess,
	frame []byte,
	remaining time.Duration,
) Outcome {
	lifecycleStarted := time.Now()
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
	stdinHandle := process.pipes.stdinWrite
	process.pipes.stdinWrite = 0
	inputWriter := newInputWriter(stdinHandle)
	go inputWriter.publish(frame, input)
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
	inputResult := awaitInput(inputWriter, cleanupDeadline, joinDeadline)
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
	outcome.Resources, cleanupDeadline = measureResources(
		cleanupDeadline,
		func() Resources { return processResources(process.job, process.info.Process) },
	)
	closeComplete, closeErr := finaliseCleanup(cleanupDeadline, process.close)
	outcome = applyFinalCleanup(outcome, closeComplete, closeErr)
	outcome.Timings.Input = inputResult.duration
	outcome.Timings.Output = out.duration
	outcome.Timings.Diagnostics = diagnostics.duration
	outcome.Timings.Lifecycle = time.Since(lifecycleStarted)
	outcome.Timings.InputMeasured = true
	outcome.Timings.OutputMeasured = true
	outcome.Timings.DiagnosticsMeasured = true
	outcome.Timings.LifecycleMeasured = true
	return outcome
}

func unappliedInputResult(result inputResult, applied bool) inputResult {
	if applied {
		result.err = nil
	}
	return result
}

func executionAllowance(remaining time.Duration) time.Duration {
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}
