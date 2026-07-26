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
	"unsafe"

	"golang.org/x/sys/windows"
)

func createRecordTemp(path, name string) (*os.File, error) {
	descriptor, err := secureDirectoryDescriptor()
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for range 8 {
		temporaryName, err := recordTempName(name)
		if err != nil {
			return nil, err
		}
		filePath := filepath.Join(path, temporaryName)
		pointer, err := windows.UTF16PtrFromString(filePath)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(
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
		file := os.NewFile(uintptr(handle), filePath)
		if file == nil {
			return nil, errors.Join(
				errors.New("create record file"),
				windows.CloseHandle(handle),
			)
		}
		return file, nil
	}
	return nil, errors.New("create unique record file")
}
