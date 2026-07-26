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
	"time"
)

func failedLaunchOutcome(
	started time.Time,
	cleanupComplete bool,
	err error,
) Outcome {
	status := StartFailed
	if !cleanupComplete {
		status = CleanupFailed
	}
	outcome := failedOutcome(status, started, err)
	outcome.CleanupComplete = cleanupComplete
	return outcome
}

func earliestDeadline(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}

func checkStartupDeadline(deadline time.Time) error {
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
