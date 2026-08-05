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

package supervision

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnavailable = errors.New("process supervision unavailable")
)

type Status string

const (
	Completed      Status = "completed"
	StartFailed    Status = "start_failed"
	TimedOut       Status = "timed_out"
	Cancelled      Status = "cancelled"
	OutputOverflow Status = "output_overflow"
	ErrorOverflow  Status = "error_overflow"
	ExitFailed     Status = "exit_failed"
	CleanupFailed  Status = "cleanup_failed"
)

type Limits struct {
	InputBytes     int
	OutputBytes    int
	ErrorBytes     int
	MemoryBytes    int
	Processes      uint32
	StartupTimeout time.Duration
	Timeout        time.Duration
	CleanupTimeout time.Duration
}

type Outcome struct {
	Status       Status
	Stdout       []byte
	Stderr       []byte
	ExitCode     uint32
	WorkerSHA256 [32]byte
	// Duration covers execution through the first terminal supervision event.
	Duration        time.Duration
	CleanupComplete bool
	Err             error
}

func New(workerPath string, limits Limits) (*Supervisor, error) {
	return newSupervisor(workerPath, limits)
}

func (supervisor *Supervisor) RunBefore(
	ctx context.Context,
	frame []byte,
	startDeadline time.Time,
) Outcome {
	return supervisor.run(ctx, frame, startDeadline)
}
