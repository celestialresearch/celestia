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
	"math"
	"os"
	"path/filepath"
	"time"
)

type Supervisor struct {
	workerPath string
	workerHash [32]byte
	limits     Limits
}

type supervisorCreationOperations struct {
	open  func(string) (*os.File, error)
	hash  func(*os.File) ([32]byte, error)
	close func(*os.File) error
}

func defaultSupervisorCreationOperations() supervisorCreationOperations {
	return supervisorCreationOperations{
		open: openLocalImage,
		hash: hashFile,
		close: func(file *os.File) error {
			return file.Close()
		},
	}
}

func newSupervisor(workerPath string, limits Limits) (*Supervisor, error) {
	return newSupervisorWith(
		workerPath,
		limits,
		defaultSupervisorCreationOperations(),
	)
}

func newSupervisorWith(
	workerPath string,
	limits Limits,
	operations supervisorCreationOperations,
) (*Supervisor, error) {
	if !validWorkerPath(workerPath) || !validLimits(limits) {
		return nil, fmt.Errorf("%w: worker path or limits", ErrInvalid)
	}
	cleanPath := filepath.Clean(workerPath)
	worker, err := operations.open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open worker: %w", ErrInvalid, err)
	}
	hash, hashErr := operations.hash(worker)
	closeErr := operations.close(worker)
	if err := errors.Join(hashErr, closeErr); err != nil {
		return nil, fmt.Errorf("%w: measure worker: %w", ErrInvalid, err)
	}
	return &Supervisor{
		workerPath: cleanPath,
		workerHash: hash,
		limits:     limits,
	}, nil
}

func validWorkerPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	volume := filepath.VolumeName(path)
	return len(volume) == 2 &&
		((volume[0] >= 'A' && volume[0] <= 'Z') ||
			(volume[0] >= 'a' && volume[0] <= 'z')) &&
		volume[1] == ':'
}

func validLimits(limits Limits) bool {
	return validStreamLimit(limits.InputBytes) &&
		validStreamLimit(limits.OutputBytes) &&
		validStreamLimit(limits.ErrorBytes) &&
		limits.MemoryBytes > 0 &&
		limits.Processes > 0 &&
		limits.StartupTimeout > 0 &&
		limits.Timeout >= 100*time.Nanosecond &&
		limits.CleanupTimeout > 0
}

func validStreamLimit(limit int) bool {
	return limit > 0 && limit < math.MaxInt
}

func (supervisor *Supervisor) run(
	ctx context.Context,
	frame []byte,
	startDeadline time.Time,
) Outcome {
	started := time.Now()
	if ctx == nil ||
		startDeadline.IsZero() ||
		len(frame) == 0 ||
		len(frame) > supervisor.limits.InputBytes {
		outcome := failedOutcome(StartFailed, started, fmt.Errorf("%w: context or frame", ErrInvalid))
		outcome.WorkerSHA256 = supervisor.workerHash
		outcome.CleanupComplete = true
		return outcome
	}
	select {
	case <-ctx.Done():
		outcome := failedOutcome(Cancelled, started, ctx.Err())
		outcome.WorkerSHA256 = supervisor.workerHash
		outcome.CleanupComplete = true
		return outcome
	default:
	}
	if err := checkStartupDeadline(startDeadline); err != nil {
		outcome := failedOutcome(StartFailed, started, err)
		outcome.WorkerSHA256 = supervisor.workerHash
		outcome.CleanupComplete = true
		return outcome
	}
	startupDeadline := earliestDeadline(
		startDeadline,
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
	process, hash, cleanupComplete, err := supervisor.launch(ctx, startupDeadline)
	if err != nil {
		outcome := failedLaunchOutcome(started, cleanupComplete, err)
		outcome.WorkerSHA256 = supervisor.workerHash
		if hash != ([32]byte{}) {
			outcome.WorkerSHA256 = hash
		}
		outcome.CleanupComplete = cleanupComplete
		return outcome
	}
	remaining := executionRemaining(
		process.started,
		supervisor.limits.Timeout,
		time.Now(),
	)
	outcome := supervisor.observe(ctx, process, frame, remaining)
	outcome.WorkerSHA256 = hash
	return outcome
}

func failedOutcome(status Status, started time.Time, err error) Outcome {
	return Outcome{
		Status:   status,
		Duration: time.Since(started),
		Err:      err,
	}
}
