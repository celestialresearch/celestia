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
	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

func callerProcess(process supervision.Outcome) supervision.Outcome {
	process.Stdout = nil
	process.Stderr = nil
	process.Timings = supervision.Timings{}
	return process
}

func projectDiagnostics(
	status workerprotocol.Status,
	values []workerprotocol.Diagnostic,
) []Diagnostic {
	if status == workerprotocol.Completed || len(values) == 0 {
		return nil
	}
	diagnostics := make([]Diagnostic, len(values))
	for index, value := range values {
		code := diagnosticCode(status, value.Code)
		diagnostics[index] = Diagnostic{
			Code:    code,
			Message: diagnosticMessage(code),
		}
	}
	return diagnostics
}

func diagnosticCode(status workerprotocol.Status, code string) string {
	if status == workerprotocol.Rejected && code == "invalid_reference" {
		return code
	}
	return "worker_failure"
}

func diagnosticMessage(code string) string {
	switch code {
	case "invalid_reference":
		return "The worker rejected the URL reference"
	default:
		return "The worker reported a failure"
	}
}
