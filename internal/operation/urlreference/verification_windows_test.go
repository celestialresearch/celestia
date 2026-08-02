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
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"context"
	"testing"
)

func TestOperationVerifiesWorker(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		mode     urlreference.Mode
		expected string
	}{
		{
			name:     "defang",
			input:    "https://example.test/path",
			mode:     urlreference.Defang,
			expected: "hxxps://example[.]test/path",
		},
		{
			name:     "fang",
			input:    "hxxps://example[.]test/path",
			mode:     urlreference.Fang,
			expected: "https://example.test/path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertVerifiedWorker(t, test.input, test.mode, test.expected)
		})
	}
}

func assertVerifiedWorker(t *testing.T, input string, mode urlreference.Mode, expected string) {
	t.Helper()

	operation, err := newTestOperation(t, testWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(context.Background(), input, mode)
	if result.Status != Verified ||
		result.Response == nil ||
		!result.Verification.Matched ||
		result.Verification.Expected != expected ||
		result.Response.Output == nil ||
		*result.Response.Output != expected {
		t.Fatalf("result=%+v", result)
	}
	records, err := operation.store.Inspect(result.AttemptID)
	if err != nil {
		t.Fatalf("inspect attempt: %v", err)
	}
	if records.Observation == nil ||
		records.Observation.TerminalStatus != string(Verified) ||
		!records.Observation.VerificationPass {
		t.Fatalf("records=%+v", records)
	}
}

func TestOperationRejectsSemanticLie(t *testing.T) {
	operation, err := newTestOperation(t, testHostileWorker(t))
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	result := operation.Execute(
		context.Background(),
		"https://example.test",
		urlreference.Defang,
	)
	if result.Status != ExecutedUnverified ||
		result.Response == nil ||
		result.Verification.Matched {
		t.Fatalf("result=%+v", result)
	}
}
