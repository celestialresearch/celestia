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
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/attempt"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestOperationReportsStagingFailure(t *testing.T) {
	root := testEvidenceRoot(t)
	operation, err := New(testWorker(t), root)
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove evidence root: %v", err)
	}
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("replace evidence root: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Indeterminate || result.AttemptID != "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationRetainsCommittedStagingIdentity(t *testing.T) {
	operation, err := New(testWorker(t), testEvidenceRoot(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	injected := errors.New("marker finalisation failed")
	operation.stage = func(
		accepted urladmission.Accepted,
		_ time.Time,
	) (*attemptstore.Attempt, error) {
		return nil, &attemptstore.CommittedStageError{
			AttemptID: accepted.Request.AttemptID,
			Err:       injected,
		}
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Indeterminate ||
		result.AttemptID == "" ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, injected) {
		t.Fatalf("result=%+v", result)
	}
}

func TestObservationPreservesProcessFailure(t *testing.T) {
	result := Result{
		Status:    Failed,
		AttemptID: "attempt",
		Process: supervision.Outcome{
			Status: supervision.ExitFailed,
			Err:    context.Canceled,
		},
		Err: ErrProtocol,
	}
	observation := observationFrom(result, result.Process)
	if observation.ProtocolStatus != protocolNotRun ||
		observation.ProcessError == "" ||
		observation.TerminalStatus != string(Failed) {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestObservationMapsProtocolState(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		expected string
	}{
		{name: "not run", result: Result{}, expected: protocolNotRun},
		{
			name: "valid",
			result: Result{
				Response: &workerprotocol.Response{},
			},
			expected: protocolValid,
		},
		{
			name: "rejected",
			result: Result{
				Process: supervision.Outcome{
					Status: supervision.Completed,
				},
				Err: ErrProtocol,
			},
			expected: protocolRejected,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := observationFrom(test.result, test.result.Process).ProtocolStatus; actual != test.expected {
				t.Fatalf("status=%q, want %q", actual, test.expected)
			}
		})
	}
}

func TestExecuteRecordsPublicationFailure(t *testing.T) {
	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	failure := errors.Join(attemptstore.ErrPublication, errors.New("write fixture"))
	operation.publish = func(
		attempt *attemptstore.Attempt,
		_ attemptstore.Observation,
	) error {
		return errors.Join(failure, attempt.Close())
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != Indeterminate ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, failure) {
		t.Fatalf("result=%+v", result)
	}
}

func TestPublishReleaseFailurePreservesTerminalStatus(t *testing.T) {
	result := Result{Status: Verified}
	applyPublishError(&result, attemptstore.ErrRelease)
	if result.Status != Verified {
		t.Fatalf("release failure changed status to %q", result.Status)
	}
	if !errors.Is(result.Err, ErrCleanup) ||
		!errors.Is(result.Err, attemptstore.ErrRelease) {
		t.Fatalf("release failure not reported: %v", result.Err)
	}
	if errors.Is(result.Err, ErrPersistence) {
		t.Fatalf("release failure reported as persistence failure: %v", result.Err)
	}
}

func TestPublicationFailureOverridesReleaseFailure(t *testing.T) {
	result := Result{Status: Verified}
	applyPublishError(
		&result,
		errors.Join(attemptstore.ErrPublication, attemptstore.ErrRelease),
	)
	if result.Status != Indeterminate ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, ErrCleanup) {
		t.Fatalf("combined publication result=%+v", result)
	}
}

func TestUnexpectedPublishErrorIsIndeterminate(t *testing.T) {
	unexpected := errors.New("unexpected publication error")
	result := Result{Status: Verified}
	applyPublishError(&result, unexpected)
	if result.Status != Indeterminate ||
		!errors.Is(result.Err, ErrPersistence) ||
		!errors.Is(result.Err, unexpected) {
		t.Fatalf("result=%+v", result)
	}
}
