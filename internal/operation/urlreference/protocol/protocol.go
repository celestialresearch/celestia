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

package workerprotocol

import (
	"errors"
	"regexp"
)

const (
	ProtocolVersion  = 1
	OperationID      = "url-reference"
	OperationVersion = 1
	WorkerID         = "celestia-url-reference"
	WorkerVersion    = "1"
	MediaType        = "text/plain; charset=utf-8"
	MaxResponseBytes = 65536
	MaxOutputBytes   = 8192
	MaxDiagnostics   = 16
	MaxMessageBytes  = 512
	MaxDurationNS    = 2_000_000_000
	MaxJSONDepth     = 32
	InputBytes       = 4096
	StderrBytes      = 8192
	MemoryBytes      = 67108864
	Processes        = 1
	StartTimeoutMS   = 12000
	TimeoutMS        = 2000
)

var (
	errProtocol    = errors.New("invalid worker protocol")
	diagnosticCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	decimalInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	lowerHex       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Request struct {
	ProtocolVersion  int    `json:"protocol_version"`
	OperationID      string `json:"operation_id"`
	OperationVersion int    `json:"operation_version"`
	AttemptID        string `json:"attempt_id"`
	RequestNonce     string `json:"request_nonce"`
	InputMediaType   string `json:"input_media_type"`
	InputLength      int    `json:"input_length"`
	InputSHA256      string `json:"input_sha256"`
	Mode             string `json:"mode"`
	Deadline         string `json:"deadline"`
	TimeoutMS        int    `json:"timeout_ms"`
	Limits           Limits `json:"limits"`
	Input            string `json:"input"`
}

type Limits struct {
	InputBytes  int `json:"input_bytes"`
	OutputBytes int `json:"output_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	MemoryBytes int `json:"memory_bytes"`
	Processes   int `json:"processes"`
}

type Response struct {
	ProtocolVersion  int          `json:"protocol_version"`
	OperationID      string       `json:"operation_id"`
	OperationVersion int          `json:"operation_version"`
	AttemptID        string       `json:"attempt_id"`
	RequestNonce     string       `json:"request_nonce"`
	WorkerID         string       `json:"worker_id"`
	WorkerVersion    string       `json:"worker_version"`
	Status           Status       `json:"status"`
	OutputMediaType  *string      `json:"output_media_type,omitempty"`
	OutputLength     *int         `json:"output_length,omitempty"`
	OutputSHA256     *string      `json:"output_sha256,omitempty"`
	Output           *string      `json:"output,omitempty"`
	Diagnostics      []Diagnostic `json:"diagnostics"`
	DurationNS       int64        `json:"duration_ns"`
}

type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Status string

const (
	Completed Status = "completed"
	Rejected  Status = "rejected"
	Failed    Status = "failed"
)

type responseCorrelation struct {
	attemptID string
	nonce     string
	mediaType string
}
