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

package filereplace

import (
	"context"
	"errors"

	"celestia.research/celestia/internal/operation/filereplace/admission"
	"celestia.research/celestia/internal/operation/filereplace/attempt"
)

var (
	ErrUnsupported   = errors.New("file replacement unsupported")
	ErrConfiguration = errors.New("invalid file-replacement configuration")
	ErrTarget        = errors.New("unsafe file-replacement target")
	ErrPrecondition  = errors.New("file-replacement precondition changed")
	ErrIndeterminate = errors.New("file-replacement outcome indeterminate")
)

type Config struct {
	TargetRoot   string
	EvidenceRoot string
}

type Result struct {
	AttemptID       string
	State           attempt.State
	ObservedSHA256  [32]byte
	CleanupComplete bool
}

type Operation struct {
	platform platformOperation
}

func New(config Config) (*Operation, error) {
	platform, err := newPlatformOperation(config)
	if err != nil {
		return nil, err
	}
	return &Operation{platform: platform}, nil
}

func (o *Operation) Execute(ctx context.Context, request admission.Request) (Result, error) {
	if o == nil {
		return Result{}, ErrConfiguration
	}
	return o.platform.execute(ctx, request)
}

func (o *Operation) Recover(ctx context.Context) ([]Result, error) {
	if o == nil {
		return nil, ErrConfiguration
	}
	return o.platform.recover(ctx)
}

func (o *Operation) Inspect(attemptID string) (Result, error) {
	if o == nil {
		return Result{}, ErrConfiguration
	}
	return o.platform.inspect(attemptID)
}

func (o *Operation) Close() error {
	if o == nil {
		return nil
	}
	return o.platform.close()
}
