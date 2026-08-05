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
	"testing"
	"time"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/transform"
)

func TestOperationMeasuresEveryPhase(t *testing.T) {
	operation, err := New(
		locateWorker(t, "celestia-url-reference.exe"),
		testEvidenceRoot(t),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, timings := operation.executeMeasured(
		context.Background(),
		"https://example.test/path",
		urlreference.Defang,
	)
	if result.Status != Verified {
		t.Fatalf("status = %s, error = %v", result.Status, result.Err)
	}
	if timings.measured != allMeasuredPhases {
		t.Fatalf("measured phases = %016b, want %016b", timings.measured, allMeasuredPhases)
	}
	assertPhaseDurations(t, timings)
	if result.Process.Timings != (supervision.Timings{}) {
		t.Fatal("caller result exposes internal phase timings")
	}
}

func TestOperationDoesNotMeasureMissingVerification(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	admittedAt := time.Now().UTC()
	accepted, err := urladmission.Admit(
		"https://rejected.test",
		urlreference.Defang,
		admittedAt,
	)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	_, _, timings := operation.executeAcceptedMeasured(
		context.Background(),
		accepted,
		admittedAt,
	)
	if !timings.ProtocolMeasured || !timings.WorkerMeasured ||
		timings.VerificationMeasured {
		t.Fatalf("rejected response timings = %+v", timings)
	}
}

func assertPhaseDurations(t *testing.T, timings operationTimings) {
	t.Helper()
	for name, duration := range map[string]time.Duration{
		"request":       timings.Request,
		"admission":     timings.Admission,
		"staging":       timings.Staging,
		"preparation":   timings.Preparation,
		"process start": timings.ProcessStart,
		"input":         timings.Input,
		"worker":        timings.Worker,
		"output":        timings.Output,
		"diagnostics":   timings.Diagnostics,
		"lifecycle":     timings.Lifecycle,
		"protocol":      timings.Protocol,
		"verification":  timings.Verification,
		"observation":   timings.Observation,
		"publication":   timings.Publication,
		"receipt":       timings.Receipt,
		"total":         timings.Total,
	} {
		if duration < 0 {
			t.Errorf("%s duration = %s", name, duration)
		}
		if duration > timings.Total {
			t.Errorf("%s duration %s exceeds total %s", name, duration, timings.Total)
		}
	}
	if timings.Total <= 0 || timings.Preparation <= 0 ||
		timings.ProcessStart <= 0 || timings.Lifecycle <= 0 ||
		timings.Publication <= 0 {
		t.Fatalf("material phase timings = %+v", timings)
	}
}

func BenchmarkOperation(b *testing.B) {
	operation, err := New(
		locateWorker(b, "celestia-url-reference.exe"),
		testEvidenceRoot(b),
	)
	if err != nil {
		b.Fatalf("new operation: %v", err)
	}
	b.ResetTimer()
	for range b.N {
		result := operation.Execute(
			context.Background(),
			"https://example.test/path",
			urlreference.Defang,
		)
		if result.Status != Verified {
			b.Fatalf("status=%s error=%v", result.Status, result.Err)
		}
	}
}
