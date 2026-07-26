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
	"fmt"
	"os"
)

var (
	errLockHeld        = errors.New("attempt lock held")
	errLockUnsupported = errors.New("attempt locks unsupported")
)

func openAttemptLockFile(root *os.Root, _ string, name string, create bool) (*os.File, error) {
	file, err := root.OpenFile(name, os.O_RDWR, 0o600)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open attempt lock: %w", err)
	}
	if !create {
		return nil, ErrCorrupt
	}
	file, err = root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return root.OpenFile(name, os.O_RDWR, 0o600)
	}
	if err != nil {
		return nil, fmt.Errorf("create attempt lock: %w", err)
	}
	return file, nil
}

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
