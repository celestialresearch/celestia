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

//go:build !windows

package processsupervision

import (
	"context"
	"fmt"
)

func newSupervisor(string, Limits) (*Supervisor, error) {
	return nil, fmt.Errorf("%w: native containment is not qualified", ErrUnavailable)
}

func (*Supervisor) run(context.Context, []byte) Outcome {
	return Outcome{
		Status: StartFailed,
		Err:    fmt.Errorf("%w: native containment is not qualified", ErrUnavailable),
	}
}
