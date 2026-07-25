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

package processsupervision

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnavailable = errors.New("process supervision unavailable")
	ErrInvalid     = errors.New("invalid process supervision configuration")
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
	Timeout        time.Duration
	CleanupTimeout time.Duration
}

type Outcome struct {
	Status          Status
	Stdout          []byte
	Stderr          []byte
	ExitCode        uint32
	WorkerSHA256    [32]byte
	Duration        time.Duration
	CleanupComplete bool
	Err             error
}

type Supervisor struct {
	workerPath string
	workerHash [32]byte
	limits     Limits
}

func New(workerPath string, limits Limits) (*Supervisor, error) {
	return newSupervisor(workerPath, limits)
}

func (supervisor *Supervisor) Run(ctx context.Context, frame []byte) Outcome {
	return supervisor.run(ctx, frame)
}

func validLimits(limits Limits) bool {
	return limits.InputBytes > 0 &&
		limits.OutputBytes > 0 &&
		limits.ErrorBytes > 0 &&
		limits.MemoryBytes > 0 &&
		limits.Processes > 0 &&
		limits.Timeout > 0 &&
		limits.CleanupTimeout > 0
}
