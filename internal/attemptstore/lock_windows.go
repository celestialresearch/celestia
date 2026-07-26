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
	"os"

	"golang.org/x/sys/windows"
)

var errLockHeld = errors.New("attempt lock held")

func lockAttemptFile(file *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errLockHeld
	}
	return err
}

func unlockAttemptFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}

func secureLockFile(file *os.File, _ os.FileInfo) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&information,
	); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 {
		return ErrCorrupt
	}
	return nil
}

func syncAttemptLockDirectory(directory string) error {
	path, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = windows.CloseHandle(handle)
	}()
	return windows.FlushFileBuffers(handle)
}
