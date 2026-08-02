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
)

var errParentContext = errors.New("parent execution context ended")

func failedLaunchOutcome(
	started time.Time,
	cleanupComplete bool,
	err error,
) Outcome {
	status := StartFailed
	if errors.Is(err, errParentContext) {
		status = Cancelled
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

func checkStartupContext(ctx context.Context, deadline time.Time) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", errParentContext, ctx.Err())
	default:
		return checkStartupDeadline(deadline)
	}
}

func executionRemaining(
	started time.Time,
	limit time.Duration,
	now time.Time,
) time.Duration {
	return started.Add(limit).Sub(now)
}
