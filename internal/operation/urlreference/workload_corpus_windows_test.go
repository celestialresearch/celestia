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

	attemptstore "celestia.research/celestia/internal/operation/urlreference/attempt"
	"celestia.research/celestia/internal/operation/urlreference/transform"
)

func TestPerformanceWorkloadCorpusCoverage(t *testing.T) {
	corpus := loadPerformanceCorpus(t)
	seen := map[string]performanceWorkloadCase{}
	for _, c := range corpus.Cases {
		seen[c.Class] = c
	}
	for _, class := range acceptedClasses {
		c, ok := seen[class]
		if !ok || c.Kind != "accepted" || len(c.Paths) != 2 || c.Paths[0] != "cold" || c.Paths[1] != "warm" {
			t.Errorf("accepted class %s lacks exact cold and warm paths", class)
		}
	}
	for _, class := range faultClasses {
		if _, ok := seen[class]; !ok {
			t.Errorf("missing fault class %s", class)
		}
	}
}

func TestPerformanceWorkloadCorpusFullOperation(t *testing.T) {
	corpus := loadPerformanceCorpus(t)
	warm, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new warm operation: %v", err)
	}
	for _, c := range corpus.Cases {
		if c.Kind != "accepted" {
			continue
		}
		for _, path := range c.Paths {
			t.Run(c.ID+"/"+path, func(t *testing.T) {
				executeCorpusWorkload(t, warm, c, path)
			})
		}
	}
}

func executeCorpusWorkload(t *testing.T, warm *Operation, c performanceWorkloadCase, path string) {
	t.Helper()
	op := corpusOperation(t, warm, path)
	result, timings := op.executeMeasured(context.Background(), c.Input, urlreference.Mode(c.Mode))
	assertCorpusResult(t, result, timings, c.Expected)
	assertCorpusEvidence(t, op, result.AttemptID, c.Expected)
}

func corpusOperation(t *testing.T, warm *Operation, path string) *Operation {
	t.Helper()
	if path == "warm" {
		return warm
	}
	op, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new cold operation: %v", err)
	}
	return op
}

func assertCorpusResult(t *testing.T, result Result, timings operationTimings, expected string) {
	t.Helper()
	if result.Status != Verified || result.Response == nil || result.Response.Output == nil || *result.Response.Output != expected || !result.Process.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
	if timings.measured != allMeasuredPhases {
		t.Fatalf("phases=%016b want=%016b", timings.measured, allMeasuredPhases)
	}
	assertPhaseDurations(t, timings)
}

func assertCorpusEvidence(t *testing.T, op *Operation, attemptID, expected string) {
	t.Helper()
	records, err := op.store.Inspect(attemptID)
	if err != nil || records.Observation == nil || records.Observation.TerminalStatus != string(Verified) || !records.Observation.CleanupComplete || records.Observation.ExpectedOutput != expected || !records.Observation.VerificationPass || records.Observation.VerificationID != attemptstore.URLVerifierID || records.Observation.VerificationVer != attemptstore.URLVerifierVersion {
		t.Fatalf("inspect=%+v err=%v", records, err)
	}
}
