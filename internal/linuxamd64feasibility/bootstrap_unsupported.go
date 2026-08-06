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

//go:build !linux || !amd64

package linuxamd64feasibility

import (
	"errors"
	"os"
)

var errBootstrapUnsupported = errors.New("linux AMD64 bootstrap required")

func Bootstrap(*os.File, *os.File, *os.File) error {
	return errBootstrapUnsupported
}
