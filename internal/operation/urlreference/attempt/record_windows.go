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

type recordCreationOperations struct {
	descriptor  func() (*windows.SECURITY_DESCRIPTOR, error)
	name        func(string) (string, error)
	encode      func(string) (*uint16, error)
	create      func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error)
	newFile     func(uintptr, string) *os.File
	closeHandle func(windows.Handle) error
}

func createRecordTemp(path, name string) (*os.File, error) {
	return createRecordTempWith(path, name, recordCreationOperations{
		descriptor:  secureDirectoryDescriptor,
		name:        recordTempName,
		encode:      windows.UTF16PtrFromString,
		create:      windows.CreateFile,
		newFile:     os.NewFile,
		closeHandle: windows.CloseHandle,
	})
}

func createRecordTempWith(
	path, name string,
	operations recordCreationOperations,
) (*os.File, error) {
	descriptor, err := operations.descriptor()
	if err != nil {
		return nil, err
	}
	attributes := ownedSecurityAttributes(descriptor)
	for range 8 {
		temporaryName, err := operations.name(name)
		if err != nil {
			return nil, err
		}
		filePath := filepath.Join(path, temporaryName)
		pointer, err := operations.encode(filePath)
		if err != nil {
			return nil, err
		}
		handle, err := operations.create(
			pointer,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			&attributes,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH,
			0,
		)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) ||
			errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		file := operations.newFile(uintptr(handle), filePath)
		if file == nil {
			return nil, errors.Join(
				errors.New("create record file"),
				operations.closeHandle(handle),
			)
		}
		return file, nil
	}
	return nil, errors.New("create unique record file")
}
