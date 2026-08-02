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
