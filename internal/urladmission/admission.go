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

// Package urladmission decides whether a URL-reference request may execute.
package urladmission

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"celestia.research/celestia/internal/operation/urlreference/transform"
	"celestia.research/celestia/internal/operation/urlreference/protocol"
)

const identityBytes = 32

var ErrRejected = errors.New("url-reference admission rejected")

type Accepted struct {
	Request workerprotocol.Request
	Frame   []byte
}

func Admit(input string, mode urlreference.Mode, admittedAt time.Time) (Accepted, error) {
	return admit(input, mode, admittedAt, rand.Reader)
}

func admit(
	input string,
	mode urlreference.Mode,
	admittedAt time.Time,
	randomness io.Reader,
) (Accepted, error) {
	if admittedAt.Location() != time.UTC {
		return Accepted{}, reject("admission time must be UTC")
	}
	if mode != urlreference.Fang && mode != urlreference.Defang {
		return Accepted{}, reject("unsupported mode")
	}
	if err := urlreference.ValidateInput(input); err != nil {
		return Accepted{}, reject("input: %v", err)
	}

	attemptID, err := identity(randomness)
	if err != nil {
		return Accepted{}, fmt.Errorf("generate attempt identity: %w", err)
	}
	nonce, err := identity(randomness)
	if err != nil {
		return Accepted{}, fmt.Errorf("generate request nonce: %w", err)
	}
	if nonce == attemptID {
		return Accepted{}, errors.New("request nonce repeated attempt identity")
	}
	inputHash := sha256.Sum256([]byte(input))
	request := workerprotocol.Request{
		ProtocolVersion:  workerprotocol.ProtocolVersion,
		OperationID:      workerprotocol.OperationID,
		OperationVersion: workerprotocol.OperationVersion,
		AttemptID:        attemptID,
		RequestNonce:     nonce,
		InputMediaType:   workerprotocol.MediaType,
		InputLength:      len(input),
		InputSHA256:      hex.EncodeToString(inputHash[:]),
		Mode:             string(mode),
		Deadline: admittedAt.Add(
			time.Duration(workerprotocol.StartTimeoutMS) * time.Millisecond,
		).Format(time.RFC3339Nano),
		TimeoutMS: workerprotocol.TimeoutMS,
		Limits: workerprotocol.Limits{
			InputBytes:  workerprotocol.InputBytes,
			OutputBytes: workerprotocol.MaxOutputBytes,
			StderrBytes: workerprotocol.StderrBytes,
			MemoryBytes: workerprotocol.MemoryBytes,
			Processes:   workerprotocol.Processes,
		},
		Input: input,
	}
	frame, _, err := workerprotocol.EncodeRequest(request, admittedAt)
	if err != nil {
		return Accepted{}, fmt.Errorf("encode admitted request: %w", err)
	}
	return Accepted{Request: request, Frame: frame}, nil
}

func identity(randomness io.Reader) (string, error) {
	var value [identityBytes]byte
	if _, err := io.ReadFull(randomness, value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func reject(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, arguments...))
}
