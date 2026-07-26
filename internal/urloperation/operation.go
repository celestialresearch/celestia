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

package urloperation

import (
	"errors"

	"celestia.research/governed-operation/internal/processsupervision"
	"celestia.research/governed-operation/internal/workerprotocol"
)

const (
	VerifierID      = "go-url-reference"
	VerifierVersion = "0"
)

var (
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

type Result struct {
	Status       Status
	Process      processsupervision.Outcome
	Response     *workerprotocol.Response
	Verification Verification
	AttemptID    string
	Err          error
}
