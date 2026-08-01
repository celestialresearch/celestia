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

//go:build !windows || (windows && !amd64)

package urloperation

import (
	"context"
	"fmt"

	"celestia.research/celestia/internal/execution/supervision"
	"celestia.research/celestia/internal/operation/urlreference/transform"
)

type Operation struct{}

func New(
	string,
	string,
) (*Operation, error) {
	return nil, fmt.Errorf(
		"configure URL operation: %w",
		supervision.ErrUnavailable,
	)
}

func (*Operation) Execute(context.Context, string, urlreference.Mode) Result {
	return Result{
		Status: Failed,
		Err:    supervision.ErrUnavailable,
	}
}
