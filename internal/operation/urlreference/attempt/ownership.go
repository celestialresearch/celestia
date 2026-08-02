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
	"fmt"
	"os"
	"path/filepath"
)

type ownershipCreationOperations struct {
	lstat  func(*os.Root, string) (os.FileInfo, error)
	open   func(*os.Root, string, string, bool) (*os.File, error)
	stat   func(*os.File) (os.FileInfo, error)
	secure func(*os.File, os.FileInfo) error
	sync   func(*os.File, string) error
	close  func(*os.File) error
}

type ownershipInspectionOperations struct {
	lstat    func(*os.Root, string) (os.FileInfo, error)
	linked   func(string, os.FileInfo) bool
	open     func(*os.Root, string, string) (*os.File, error)
	validate func(*os.File, os.FileInfo) error
	close    func(*os.File) error
}

const ownershipMarkerSuffix = ".owned"

func (store *Store) createOwnershipMarker(attemptID string) (err error) {
	_, err = store.createOwnershipMarkerState(attemptID)
	return err
}

func (store *Store) createOwnershipMarkerState(
	attemptID string,
) (created bool, err error) {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return false, err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	return createOwnershipMarkerWith(
		root,
		directory,
		attemptID,
		ownershipCreationOperations{
			lstat: func(root *os.Root, name string) (os.FileInfo, error) {
				return root.Lstat(name)
			},
			open: openAttemptLockFile,
			stat: func(file *os.File) (os.FileInfo, error) {
				return file.Stat()
			},
			secure: secureLockFile,
			sync:   syncAttemptLock,
			close:  (*os.File).Close,
		},
	)
}

func createOwnershipMarkerWith(
	root *os.Root,
	directory,
	attemptID string,
	operations ownershipCreationOperations,
) (bool, error) {
	name := attemptID + ownershipMarkerSuffix
	if _, err := operations.lstat(root, name); err == nil {
		return false, ErrDuplicate
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect attempt ownership marker: %w", err)
	}
	file, err := operations.open(root, directory, name, true)
	if err != nil {
		return false, fmt.Errorf("create attempt ownership marker: %w", err)
	}
	info, statErr := operations.stat(file)
	var secureErr error
	if statErr == nil {
		secureErr = operations.secure(file, info)
	}
	syncErr := operations.sync(file, directory)
	closeErr := operations.close(file)
	if err := errors.Join(statErr, secureErr, syncErr, closeErr); err != nil {
		return true, fmt.Errorf("secure attempt ownership marker: %w", err)
	}
	return true, nil
}

func (store *Store) hasOwnershipMarker(attemptID string) (present bool, err error) {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return false, err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	return hasOwnershipMarkerWith(
		root,
		directory,
		attemptID,
		ownershipInspectionOperations{
			lstat: func(root *os.Root, name string) (os.FileInfo, error) {
				return root.Lstat(name)
			},
			linked:   pathIsLinked,
			open:     openLockFileReadOnly,
			validate: validateLockFile,
			close:    (*os.File).Close,
		},
	)
}

func hasOwnershipMarkerWith(
	root *os.Root,
	directory,
	attemptID string,
	operations ownershipInspectionOperations,
) (present bool, err error) {
	name := attemptID + ownershipMarkerSuffix
	pathInfo, err := operations.lstat(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect attempt ownership marker: %w", err)
	}
	if !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		operations.linked(filepath.Join(directory, name), pathInfo) {
		return false, ErrCorrupt
	}
	file, err := operations.open(root, directory, name)
	if err != nil {
		return false, fmt.Errorf("open attempt ownership marker: %w", err)
	}
	defer func() {
		err = errors.Join(err, operations.close(file))
	}()
	if err := operations.validate(file, pathInfo); err != nil {
		return false, err
	}
	return true, nil
}
