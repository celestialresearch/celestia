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
)

type recordRepairOperations struct {
	openRoot      func(string) (*os.Root, error)
	closeRoot     func(*os.Root) error
	openDirectory func(*os.Root, string) (*os.File, error)
	readDirectory func(*os.File) ([]os.DirEntry, error)
	closeFile     func(*os.File) error
	lstat         func(*os.Root, string) (os.FileInfo, error)
	invalid       func(string, os.FileInfo) bool
	remove        func(*os.Root, string) error
	confirm       func(string) error
}

func repairInterruptedRecords(path string) (err error) {
	return repairInterruptedRecordsWith(
		path,
		recordRepairOperations{
			openRoot:  os.OpenRoot,
			closeRoot: (*os.Root).Close,
			openDirectory: func(root *os.Root, name string) (*os.File, error) {
				return root.Open(name)
			},
			readDirectory: func(directory *os.File) ([]os.DirEntry, error) {
				return directory.ReadDir(-1)
			},
			closeFile: (*os.File).Close,
			lstat: func(root *os.Root, name string) (os.FileInfo, error) {
				return root.Lstat(name)
			},
			invalid: invalidRecordFile,
			remove: func(root *os.Root, name string) error {
				return root.Remove(name)
			},
			confirm: confirmPublication,
		},
	)
}

func repairInterruptedRecordsWith(
	path string,
	operations recordRepairOperations,
) (err error) {
	root, err := operations.openRoot(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, operations.closeRoot(root))
	}()
	directory, err := operations.openDirectory(root, ".")
	if err != nil {
		return err
	}
	entries, readErr := operations.readDirectory(directory)
	closeErr := operations.closeFile(directory)
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !recordTemporary(entry.Name()) {
			continue
		}
		info, err := operations.lstat(root, entry.Name())
		if err != nil ||
			operations.invalid(filepath.Join(path, entry.Name()), info) {
			return ErrCorrupt
		}
		if err := operations.remove(root, entry.Name()); err != nil {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return operations.confirm(path)
}

func recordTemporary(candidate string) bool {
	for _, record := range recordNames() {
		if temporaryRecordName(record, candidate) {
			return true
		}
	}
	return false
}
