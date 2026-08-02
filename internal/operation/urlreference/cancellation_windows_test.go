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
	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/attempt"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestOperationPreservesTermination(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	tests := []struct {
		name       string
		admittedAt time.Time
		context    func() context.Context
		status     Status
	}{
		{
			name:       "admitted deadline",
			admittedAt: time.Now().UTC().Add(-13 * time.Second),
			context:    context.Background,
			status:     TimedOut,
		},
		{
			name:       "caller cancellation",
			admittedAt: time.Now().UTC(),
			context: func() context.Context {
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				return cancelled
			},
			status: Cancelled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accepted := admittedFixture(t, test.admittedAt)
			result, _ := operation.executeAccepted(
				test.context(),
				accepted,
				test.admittedAt,
			)
			if result.Status != test.status {
				t.Fatalf("status=%s process=%s error=%v", result.Status, result.Process.Status, result.Err)
			}
		})
	}
}

func TestOperationPublishesCallerDeadline(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted := admittedFixture(t, admittedAt)
	attempt, err := operation.store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	process := supervision.Outcome{
		Status:          supervision.Cancelled,
		Err:             context.DeadlineExceeded,
		CleanupComplete: true,
		Duration:        time.Nanosecond,
	}
	result := Result{
		AttemptID: accepted.Request.AttemptID,
		Status:    terminalStatus(process),
		Process:   callerProcess(process),
		Err:       errors.Join(ErrProcess, process.Err),
	}
	if err := attempt.Publish(observationFrom(result, process)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil ||
		records.Observation.ProcessStatus != string(supervision.Cancelled) ||
		records.Observation.TerminalStatus != string(TimedOut) {
		t.Fatalf("records=%+v", records)
	}
}

func TestTerminalStatusPreservesPrimaryOutcomeDuringCleanupFailure(t *testing.T) {
	tests := []struct {
		status supervision.Status
		err    error
		want   Status
	}{
		{status: supervision.TimedOut, err: context.DeadlineExceeded, want: TimedOut},
		{status: supervision.Cancelled, err: context.Canceled, want: Cancelled},
		{status: supervision.ExitFailed, err: errors.New("process failed"), want: Failed},
		{status: supervision.Completed, err: errors.New("cleanup failed"), want: Failed},
	}
	for _, test := range tests {
		process := supervision.Outcome{
			Status:          test.status,
			CleanupComplete: false,
			Err:             test.err,
		}
		if got := terminalStatus(process); got != test.want {
			t.Fatalf("status=%s terminal=%s want=%s", test.status, got, test.want)
		}
	}
}

func nilContext() context.Context {
	return nil
}

func TestCancellationRacingPublicationPreservesOutcome(t *testing.T) {
	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	reached := make(chan struct{})
	resume := make(chan struct{})
	var resumeOnce sync.Once
	releasePublication := func() {
		resumeOnce.Do(func() {
			close(resume)
		})
	}
	defer releasePublication()
	operation.publish = func(
		attempt *attemptstore.Attempt,
		observation attemptstore.Observation,
	) error {
		close(reached)
		<-resume
		return attempt.Publish(observation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resultChannel := make(chan Result, 1)
	go func() {
		resultChannel <- operation.Execute(
			ctx,
			"https://example.test",
			urlreference.Defang,
		)
	}()
	select {
	case <-reached:
	case <-ctx.Done():
		t.Fatalf("execution did not reach publication: %v", ctx.Err())
	}
	cancel()
	releasePublication()
	var result Result
	select {
	case result = <-resultChannel:
	case <-time.After(30 * time.Second):
		t.Fatal("execution did not return after publication")
	}
	if result.Status != Verified {
		t.Fatalf("result=%+v", result)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect result: %v", err)
	}
	if records.Observation == nil ||
		records.Observation.TerminalStatus != string(Verified) {
		t.Fatalf("records=%+v", records)
	}
}
