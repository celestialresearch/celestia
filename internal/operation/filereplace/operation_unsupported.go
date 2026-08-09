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

//go:build !windows || !amd64

package filereplace

import (
	"context"

	"celestia.research/celestia/internal/operation/filereplace/admission"
)

type platformOperation struct{}

func newPlatformOperation(Config) (platformOperation, error) {
	return platformOperation{}, ErrUnsupported
}

func (*platformOperation) execute(context.Context, admission.Request) (Result, error) {
	return Result{}, ErrUnsupported
}

func (*platformOperation) recover(context.Context) ([]Result, error) {
	return nil, ErrUnsupported
}

func (*platformOperation) inspect(string) (Result, error) { return Result{}, ErrUnsupported }

func (*platformOperation) close() error { return nil }
