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
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"testing"
	"time"
)

func TestOperationRejectsMalformedProtocol(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted := admittedFixture(t, admittedAt)
	accepted.Frame = []byte("malformed")
	result, _ := operation.executeAccepted(context.Background(), accepted, admittedAt)
	if result.Status != Failed || result.Process.Status != supervision.Completed {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationPublishesProtocolFailure(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://malformed.test",
		urlreference.Defang,
	)
	if result.Status != Failed || result.Process.Status != supervision.Completed {
		t.Fatalf("result=%+v", result)
	}
}

func TestOperationRecordsValidWorkerFailure(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		status        workerprotocol.Status
		processStatus supervision.Status
		exitCode      uint32
	}{
		{
			name:          "rejected",
			input:         "https://rejected.test",
			status:        workerprotocol.Rejected,
			processStatus: supervision.Completed,
			exitCode:      2,
		},
		{
			name:          "failed",
			input:         "https://failed.test",
			status:        workerprotocol.Failed,
			processStatus: supervision.ExitFailed,
			exitCode:      3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation, err := newTestOperation(t, testHostileWorker(t))
			if err != nil {
				t.Fatalf("new operation: %v", err)
			}
			result := operation.Execute(
				context.Background(),
				test.input,
				urlreference.Defang,
			)
			assertWorkerFailure(t, result, test.status)
			records, err := operation.store.Inspect(result.AttemptID)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			assertWorkerFailureEvidence(t, records, test.processStatus, test.exitCode)
		})
	}
}

func assertWorkerFailure(t *testing.T, result Result, status workerprotocol.Status) {
	t.Helper()
	if result.Status != Failed ||
		result.Process.Status != supervision.Completed ||
		len(result.Process.Stdout) != 0 ||
		len(result.Process.Stderr) != 0 ||
		result.Response == nil ||
		result.Response.Status != status {
		t.Fatalf("result=%+v", result)
	}
	assertProjectedDiagnostics(t, result)
}

func assertWorkerFailureEvidence(
	t *testing.T,
	records attemptstore.Records,
	processStatus supervision.Status,
	exitCode uint32,
) {
	t.Helper()
	if records.Observation == nil ||
		records.Observation.ProcessStatus != string(processStatus) ||
		records.Observation.ExitCode != exitCode ||
		records.Observation.ProtocolStatus != protocolValid ||
		records.Observation.VerificationID != "" ||
		records.Observation.TerminalStatus != string(Failed) {
		t.Fatalf("records=%+v", records)
	}
	if processStatus == supervision.ExitFailed &&
		records.Observation.ProcessError == "" {
		t.Fatalf("failed worker omitted process error: %+v", records.Observation)
	}
	if processStatus == supervision.Completed &&
		records.Observation.ProcessError != "" {
		t.Fatalf("rejected worker recorded process error: %+v", records.Observation)
	}
}
