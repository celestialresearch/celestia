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
	key        string
	once       sync.Once
	releaseErr error
}

type lockReservation struct {
	key  string
	keep bool
}

var activeAttemptLocks sync.Map

func (store *Store) acquireAttemptLock(attemptID string, create bool) (*attemptLock, error) {
	if !validIdentity(attemptID) {
		return nil, fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()
	name := attemptID + ".lock"
	key := filepath.Join(directory, name)
	reservation, err := reserveAttemptLock(key)
	if err != nil {
		return nil, err
	}
	defer reservation.abandon()
	file, err := openAttemptLockFile(root, name, create)
	if err != nil {
		return nil, err
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
	if err := syncAttemptLock(file, directory); err != nil {
		_ = unlockAttemptFile(file)
		_ = file.Close()
		return nil, fmt.Errorf("sync attempt lock: %w", err)
	}
	if err := store.validateLockIdentity(directory); err != nil {
		_ = unlockAttemptFile(file)
		_ = file.Close()
		return nil, err
	}
	reservation.keep = true
	return &attemptLock{file: file, key: key}, nil
}

func (store *Store) openLockRoot(directory string) (*os.Root, error) {
	if err := rejectLinkedAncestors(directory); err != nil {
		return nil, fmt.Errorf("inspect attempt locks: %w", err)
	}
	if err := store.validateLockIdentity(directory); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open attempt locks: %w", err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(store.lockIdentity, rootInfo) {
		_ = root.Close()
		return nil, ErrCorrupt
	}
	return root, nil
}

func (store *Store) validateLockIdentity(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !os.SameFile(store.lockIdentity, info) {
		return ErrCorrupt
	}
	return nil
}

func reserveAttemptLock(key string) (*lockReservation, error) {
	if _, loaded := activeAttemptLocks.LoadOrStore(key, struct{}{}); loaded {
		return nil, ErrActive
	}
	return &lockReservation{key: key}, nil
}

func (reservation *lockReservation) abandon() {
	if !reservation.keep {
		activeAttemptLocks.Delete(reservation.key)
	}
}

func openAttemptLockFile(root *os.Root, name string, create bool) (*os.File, error) {
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

func syncAttemptLock(file *os.File, directory string) error {
	if err := file.Sync(); err != nil {
		return err
	}
	return syncAttemptLockDirectory(directory)
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
		if closeErr == nil {
			activeAttemptLocks.Delete(lock.key)
		}
		lock.releaseErr = errors.Join(unlockErr, closeErr)
	})
	return lock.releaseErr
}
