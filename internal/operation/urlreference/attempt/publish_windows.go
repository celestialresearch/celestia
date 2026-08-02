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
	"os"
	"path/filepath"
	"unsafe"
)

type evidenceDirectoryOperations struct {
	descriptor func() (*windows.SECURITY_DESCRIPTOR, error)
	encode     func(string) (*uint16, error)
	create     func(*uint16, *windows.SecurityAttributes) error
	secure     func(string) error
	remove     func(string, string) error
	sync       func(string) error
}

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

func publishDirectory(source, target, _ string) error {
	return publishFile(source, target, "")
}
func createEvidenceDirectory(path string) error {
	return createEvidenceDirectoryWith(
		path,
		evidenceDirectoryOperations{
			descriptor: secureDirectoryDescriptor,
			encode:     windows.UTF16PtrFromString,
			create:     windows.CreateDirectory,
			secure:     secureEvidenceTree,
			remove:     removeCreatedDirectory,
			sync:       syncDirectory,
		},
	)
}

func createEvidenceDirectoryWith(
	path string,
	operations evidenceDirectoryOperations,
) error {
	parent := filepath.Dir(path)
	descriptor, err := operations.descriptor()
	if err != nil {
		return err
	}
	pointer, err := operations.encode(filepath.Clean(path))
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := operations.create(pointer, &attributes); err != nil {
		return err
	}
	if err := operations.secure(path); err != nil {
		return errors.Join(err, operations.remove(path, parent))
	}
	if err := operations.sync(parent); err != nil {
		return errors.Join(err, operations.remove(path, parent))
	}
	return nil
}

func removeCreatedDirectory(path, parent string) error {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	removeErr := root.Remove(filepath.Base(path))
	closeErr := root.Close()
	return errors.Join(removeErr, closeErr, syncDirectory(parent))
}

func pathIsLinked(path string, _ os.FileInfo) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return true
	}
	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func confirmPublication(directory string) error {
	return syncAttemptLockDirectory(directory)
}

func syncDirectory(directory string) error {
	return syncAttemptLockDirectory(directory)
}
