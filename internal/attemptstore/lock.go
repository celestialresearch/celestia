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

const ownershipMarkerSuffix = ".owned"

var activeAttemptLocks sync.Map

func (store *Store) acquireAttemptLock(
	attemptID string,
	create bool,
) (lock *attemptLock, err error) {
	if !validIdentity(attemptID) {
		return nil, fmt.Errorf("%w: attempt identity", ErrInvalid)
	}
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return nil, err
	}
	var reservation *lockReservation
	defer func() {
		lock, err = finishLockRoot(root, reservation, lock, err)
	}()
	name := attemptID + ".lock"
	key := filepath.Join(directory, name)
	reservation, err = reserveAttemptLock(key)
	if err != nil {
		return nil, err
	}
	defer reservation.abandon()
	file, err := openAttemptLockFile(root, directory, name, create)
	if err != nil {
		return nil, err
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("inspect attempt lock: %w", err),
			file.Close(),
		)
	}
	if err := validateLockFile(file, pathInfo); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := lockAttemptFile(file); err != nil {
		closeErr := file.Close()
		if errors.Is(err, errLockHeld) {
			return nil, errors.Join(ErrActive, closeErr)
		}
		return nil, errors.Join(fmt.Errorf("lock attempt: %w", err), closeErr)
	}
	if err := syncAttemptLock(file, directory); err != nil {
		return nil, errors.Join(
			fmt.Errorf("sync attempt lock: %w", err),
			unlockAttemptFile(file),
			file.Close(),
		)
	}
	if err := store.validateLockIdentity(directory); err != nil {
		return nil, errors.Join(
			err,
			unlockAttemptFile(file),
			file.Close(),
		)
	}
	reservation.keep = true
	lock = &attemptLock{file: file, key: key}
	return lock, nil
}

func finishLockRoot(
	root *os.Root,
	reservation *lockReservation,
	lock *attemptLock,
	operationErr error,
) (*attemptLock, error) {
	return finishLockRootResult(
		root.Close(),
		reservation,
		lock,
		operationErr,
	)
}

func finishLockRootResult(
	closeErr error,
	reservation *lockReservation,
	lock *attemptLock,
	operationErr error,
) (*attemptLock, error) {
	if closeErr == nil {
		return lock, operationErr
	}
	operationErr = errors.Join(operationErr, closeErr)
	if lock == nil {
		return nil, operationErr
	}
	operationErr = errors.Join(
		operationErr,
		unlockAttemptFile(lock.file),
		lock.file.Close(),
	)
	reservation.keep = false
	activeAttemptLocks.Delete(reservation.key)
	return nil, operationErr
}

func (store *Store) createOwnershipMarker(attemptID string) (err error) {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	name := attemptID + ownershipMarkerSuffix
	if _, err := root.Lstat(name); err == nil {
		return ErrDuplicate
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect attempt ownership marker: %w", err)
	}
	file, err := openAttemptLockFile(root, directory, name, true)
	if err != nil {
		return fmt.Errorf("create attempt ownership marker: %w", err)
	}
	info, statErr := file.Stat()
	var secureErr error
	if statErr == nil {
		secureErr = secureLockFile(file, info)
	}
	syncErr := syncAttemptLock(file, directory)
	closeErr := file.Close()
	if err := errors.Join(statErr, secureErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("secure attempt ownership marker: %w", err)
	}
	return nil
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
	name := attemptID + ownershipMarkerSuffix
	pathInfo, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect attempt ownership marker: %w", err)
	}
	if !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathIsLinked(filepath.Join(directory, name), pathInfo) {
		return false, ErrCorrupt
	}
	file, err := root.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("open attempt ownership marker: %w", err)
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()
	if err := validateLockFile(file, pathInfo); err != nil {
		return false, err
	}
	return true, nil
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
		return nil, errors.Join(ErrCorrupt, root.Close())
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
