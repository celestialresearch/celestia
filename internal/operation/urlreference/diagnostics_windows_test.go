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
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"fmt"
	"strings"
	"testing"
)

func assertProjectedDiagnostics(t *testing.T, result Result) {
	t.Helper()
	if result.Response == nil ||
		len(result.Response.Diagnostics) != 0 ||
		len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != "worker_failure" ||
		result.Diagnostics[0].Message != "The worker reported a failure" ||
		result.Verification.VerifierID != "" {
		t.Fatalf("result=%+v", result)
	}
	if result.Diagnostics[0].Code == "fixture_rejected" ||
		result.Diagnostics[0].Code == "fixture_failed" {
		t.Fatalf("worker-controlled code exposed: %+v", result.Diagnostics)
	}
	if strings.Contains(result.Diagnostics[0].Message, "hostile fixture") {
		t.Fatalf("worker-controlled message exposed: %+v", result.Diagnostics)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), "hostile fixture") {
		t.Fatalf("raw worker evidence retained in result")
	}
}

func TestProjectDiagnostics(t *testing.T) {
	tests := []struct {
		name    string
		status  workerprotocol.Status
		worker  string
		code    string
		message string
		count   int
	}{
		{
			name:    "known rejection",
			status:  workerprotocol.Rejected,
			worker:  "invalid_reference",
			code:    "invalid_reference",
			message: "The worker rejected the URL reference",
			count:   1,
		},
		{
			name:    "unknown failure",
			status:  workerprotocol.Failed,
			worker:  "worker_selected_code",
			code:    "worker_failure",
			message: "The worker reported a failure",
			count:   1,
		},
		{
			name:   "completed",
			status: workerprotocol.Completed,
			worker: "invalid_reference",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics := projectDiagnostics(
				test.status,
				[]workerprotocol.Diagnostic{{
					Code:    test.worker,
					Message: "worker-controlled message",
				}},
			)
			if len(diagnostics) != test.count {
				t.Fatalf("diagnostics=%+v", diagnostics)
			}
			if test.count == 0 {
				return
			}
			if diagnostics[0].Code != test.code ||
				diagnostics[0].Message != test.message {
				t.Fatalf("diagnostics=%+v", diagnostics)
			}
		})
	}
}
