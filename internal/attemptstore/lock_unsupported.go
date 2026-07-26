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

//go:build js || wasip1 || plan9

package attemptstore

import (
	"errors"
	"os"
)

var (
	errLockHeld        = errors.New("attempt lock held")
	errLockUnsupported = errors.New("attempt locks unsupported")
)

func lockAttemptFile(_ *os.File) error {
	return errLockUnsupported
}

func unlockAttemptFile(_ *os.File) error {
	return nil
}

func secureLockFile(_ *os.File, _ os.FileInfo) error {
	return nil
}

func syncAttemptLockDirectory(_ string) error {
	return nil
}
