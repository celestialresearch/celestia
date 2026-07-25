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

package attemptstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type attemptLock struct {
	file       *os.File
	once       sync.Once
	releaseErr error
}

func (store *Store) acquireAttemptLock(attemptID string, create bool) (*attemptLock, error) {
	if !validIdentity(attemptID) {
		return nil, fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	directory := filepath.Join(store.root, locksDirectory)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open attempt locks: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()
	name := attemptID + ".lock"
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	file, err := root.OpenFile(name, flags, 0o600)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return nil, ErrCorrupt
		}
		return nil, fmt.Errorf("open attempt lock: %w", err)
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect attempt lock: %w", err)
	}
	if err := validateLockFile(file, pathInfo); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := lockAttemptFile(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errLockHeld) {
			return nil, ErrActive
		}
		return nil, fmt.Errorf("lock attempt: %w", err)
	}
	return &attemptLock{file: file}, nil
}

func validateLockFile(file *os.File, pathInfo os.FileInfo) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathIsLinked(file.Name(), pathInfo) ||
		!os.SameFile(pathInfo, info) ||
		!info.Mode().IsRegular() ||
		info.Size() != 0 {
		return ErrCorrupt
	}
	return secureLockFile(file, info)
}

func (lock *attemptLock) release() error {
	lock.once.Do(func() {
		unlockErr := unlockAttemptFile(lock.file)
		closeErr := lock.file.Close()
		lock.releaseErr = errors.Join(unlockErr, closeErr)
	})
	return lock.releaseErr
}
