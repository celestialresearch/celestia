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
	"errors"
	"fmt"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
)

func evaluateResponse(
	accepted urladmission.Accepted,
	process supervision.Outcome,
	response workerprotocol.Response,
) Result {
	diagnostics := projectDiagnostics(response.Status, response.Diagnostics)
	response.Diagnostics = nil
	if response.Status != workerprotocol.Completed {
		return Result{
			Status:      Failed,
			Process:     callerProcess(process),
			Response:    &response,
			Diagnostics: diagnostics,
			Err: errors.Join(
				ErrProcess,
				fmt.Errorf("worker status %s", response.Status),
			),
		}
	}
	result := Result{
		Status:      ExecutedUnverified,
		Process:     callerProcess(process),
		Response:    &response,
		Diagnostics: diagnostics,
		Verification: Verification{
			VerifierID:      VerifierID,
			VerifierVersion: VerifierVersion,
		},
	}
	expected, err := urlreference.Transform(
		accepted.Request.Input,
		urlreference.Mode(accepted.Request.Mode),
	)
	result.Verification.Expected = expected
	result.Verification.Matched = err == nil && *response.Output == expected
	if !result.Verification.Matched {
		result.Err = ErrVerification
		return result
	}
	result.Status = Verified
	return result
}
