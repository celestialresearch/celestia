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

//go:build windows

package attemptstore

import (
	"errors"

	"golang.org/x/sys/windows"
)

func publishFile(source, target, _ string) error {
	sourcePointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(
		sourcePointer,
		targetPointer,
		windows.MOVEFILE_WRITE_THROUGH,
	)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
		errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return ErrDuplicate
	}
	return err
}
