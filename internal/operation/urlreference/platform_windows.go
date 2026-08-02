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
	"time"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

func terminalStatus(process supervision.Outcome) Status {
	switch process.Status {
	case supervision.Cancelled:
		if errors.Is(process.Err, context.DeadlineExceeded) {
			return TimedOut
		}
		return Cancelled
	case supervision.TimedOut:
		return TimedOut
	case supervision.StartFailed:
		if errors.Is(process.Err, context.DeadlineExceeded) {
			return TimedOut
		}
		return Failed
	case supervision.Completed,
		supervision.OutputOverflow,
		supervision.ErrorOverflow,
		supervision.ExitFailed,
		supervision.CleanupFailed:
		return Failed
	}
	return Failed
}

func operationLimits() supervision.Limits {
	return supervision.Limits{
		InputBytes:     workerprotocol.MaxResponseBytes,
		OutputBytes:    workerprotocol.MaxResponseBytes,
		ErrorBytes:     workerprotocol.StderrBytes,
		MemoryBytes:    workerprotocol.MemoryBytes,
		Processes:      workerprotocol.Processes,
		StartupTimeout: containmentStartupTimeout,
		Timeout:        time.Duration(workerprotocol.TimeoutMS) * time.Millisecond,
		CleanupTimeout: time.Second,
	}
}
