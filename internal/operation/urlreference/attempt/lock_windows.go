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
	"path/filepath"

	"golang.org/x/sys/windows"
)

var errLockHeld = errors.New("attempt lock held")

func openLockFileReadOnly(_ *os.Root, directory, name string) (*os.File, error) {
	return openWindowsLockFile(
		directory,
		name,
		windows.GENERIC_READ,
		windows.OPEN_EXISTING,
		nil,
	)
}

func openAttemptLockFile(_ *os.Root, directory, name string, create bool) (*os.File, error) {
	return openAttemptLockFileWith(
		directory,
		name,
		create,
		secureDirectoryDescriptor,
		openWindowsLockFile,
	)
}

func openAttemptLockFileWith(
	directory, name string,
	create bool,
	descriptorFor func() (*windows.SECURITY_DESCRIPTOR, error),
	open func(string, string, uint32, uint32, *windows.SecurityAttributes) (*os.File, error),
) (*os.File, error) {
	disposition := uint32(windows.OPEN_EXISTING)
	var attributes *windows.SecurityAttributes
	var descriptor *windows.SECURITY_DESCRIPTOR
	var err error
	if create {
		disposition = windows.CREATE_NEW
		descriptor, err = descriptorFor()
		if err != nil {
			return nil, err
		}
		value := ownedSecurityAttributes(descriptor)
		attributes = &value
	}
	file, err := open(
		directory,
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		disposition,
		attributes,
	)
	if !create && errors.Is(err, os.ErrNotExist) {
		return nil, ErrCorrupt
	}
	if errors.Is(err, windows.ERROR_FILE_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return open(
			directory,
			name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.OPEN_EXISTING,
			nil,
		)
	}
	return file, err
}

func openWindowsLockFile(
	directory,
	name string,
	access,
	disposition uint32,
	attributes *windows.SecurityAttributes,
) (*os.File, error) {
	return openWindowsLockFileWith(
		directory,
		name,
		access,
		disposition,
		attributes,
		windows.UTF16PtrFromString,
		windows.CreateFile,
		os.NewFile,
		windows.CloseHandle,
	)
}

func openWindowsLockFileWith(
	directory,
	name string,
	access,
	disposition uint32,
	attributes *windows.SecurityAttributes,
	encode func(string) (*uint16, error),
	create func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error),
	newFile func(uintptr, string) *os.File,
	closeHandle func(windows.Handle) error,
) (*os.File, error) {
	path := filepath.Join(directory, name)
	pointer, err := encode(path)
	if err != nil {
		return nil, err
	}
	handle, err := create(
		pointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		attributes,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	file := newFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.Join(
			errors.New("create attempt lock file"),
			closeHandle(handle),
		)
	}
	return file, nil
}

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
	if err := secureOwnedPath(file.Name()); err != nil {
		return err
	}
	if err := secureDirectoryACL(file.Name()); err != nil {
		return err
	}
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

func syncAttemptLockDirectory(directory string) (err error) {
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
		err = errors.Join(err, windows.CloseHandle(handle))
	}()
	return windows.FlushFileBuffers(handle)
}
