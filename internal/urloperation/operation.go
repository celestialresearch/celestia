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

// Package urloperation coordinates the governed URL-reference use case.
package urloperation

import (
	"errors"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/attempt"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

const (
	VerifierID      = attemptstore.URLVerifierID
	VerifierVersion = attemptstore.URLVerifierVersion
)

var (
	ErrAdmission    = errors.New("URL-reference admission failed")
	ErrProcess      = errors.New("worker process failed")
	ErrProtocol     = errors.New("worker protocol failed")
	ErrVerification = errors.New("worker output failed verification")
	ErrPersistence  = errors.New("attempt persistence failed")
	ErrCleanup      = errors.New("attempt ownership cleanup failed")
)

type Status string

const (
	Failed             Status = "failed"
	Rejected           Status = "rejected"
	Cancelled          Status = "cancelled"
	TimedOut           Status = "timed_out"
	ExecutedUnverified Status = "executed_unverified"
	Verified           Status = "verified"
	Indeterminate      Status = "indeterminate"
)

type Verification struct {
	VerifierID      string
	VerifierVersion string
	Expected        string
	Matched         bool
}

type Diagnostic struct {
	Code    string
	Message string
}

type Result struct {
	Status       Status
	Process      supervision.Outcome
	Response     *workerprotocol.Response
	Diagnostics  []Diagnostic
	Verification Verification
	AttemptID    string
	Err          error
}
