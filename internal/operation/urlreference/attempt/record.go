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

//go:build windows || (linux && amd64)

package attemptstore

import (
	"errors"
)

const Version = 1

const (
	attemptsDirectory = "attempts"
	pendingDirectory  = ".pending"
	locksDirectory    = ".locks"
	bundleDirectory   = "bundle"
	publicationFile   = "publication.json"
	receiptFile       = "receipt.json"
	admittedFile      = "admitted.json"
	observationFile   = "observation.json"
	recoveryFile      = "recovery.json"

	maxRecordBytes         = 256 * 1024
	maxRecoveryReasonBytes = 512
)

var (
	ErrInvalid     = errors.New("invalid attempt evidence")
	ErrDuplicate   = errors.New("duplicate attempt")
	ErrCorrupt     = errors.New("corrupt attempt evidence")
	ErrActive      = errors.New("attempt is active")
	ErrUncommitted = errors.New("attempt staging did not commit")
	ErrRelease     = errors.New("attempt ownership release failed")
	ErrPublication = errors.New("attempt publication failed")
)

type Admitted struct {
	Version       int    `json:"version"`
	AttemptID     string `json:"attempt_id"`
	AdmittedAt    string `json:"admitted_at"`
	OriginalInput string `json:"original_input"`
	RequestFrame  []byte `json:"request_frame"`
}

type Observation struct {
	Version          int    `json:"version"`
	AttemptID        string `json:"attempt_id"`
	WorkerSHA256     string `json:"worker_sha256"`
	ProcessStatus    string `json:"process_status"`
	ProcessError     string `json:"process_error,omitempty"`
	ExitCode         uint32 `json:"exit_code"`
	Stdout           []byte `json:"stdout"`
	Stderr           []byte `json:"stderr"`
	CleanupComplete  bool   `json:"cleanup_complete"`
	ProtocolStatus   string `json:"protocol_status"`
	VerificationID   string `json:"verification_id,omitempty"`
	VerificationVer  string `json:"verification_version,omitempty"`
	ExpectedOutput   string `json:"expected_output,omitempty"`
	VerificationPass bool   `json:"verification_pass"`
	TerminalStatus   string `json:"terminal_status"`
	DurationNS       int64  `json:"duration_ns"`
}

type Recovery struct {
	Version        int    `json:"version"`
	AttemptID      string `json:"attempt_id"`
	TerminalStatus string `json:"terminal_status"`
	Reason         string `json:"reason"`
}

type Receipt struct {
	Version       int    `json:"version"`
	AttemptID     string `json:"attempt_id"`
	TerminalKind  string `json:"terminal_kind"`
	AdmittedFile  string `json:"admitted_file"`
	AdmittedHash  string `json:"admitted_sha256"`
	TerminalFile  string `json:"terminal_file"`
	TerminalHash  string `json:"terminal_sha256"`
	TerminalState string `json:"terminal_status"`
}

type Publication struct {
	Version     int    `json:"version"`
	AttemptID   string `json:"attempt_id"`
	ReceiptHash string `json:"receipt_sha256"`
}

type Records struct {
	Admitted    Admitted
	Observation *Observation
	Recovery    *Recovery
	Receipt     Receipt
	Publication Publication
	receiptHash string
}
