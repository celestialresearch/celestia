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

type lockAcquisitionOperations struct {
	reserve          func(string) (*lockReservation, error)
	open             func(*os.Root, string, string, bool) (*os.File, error)
	lstat            func(*os.Root, string) (os.FileInfo, error)
	validate         func(*os.File, os.FileInfo) error
	lock             func(*os.File) error
	sync             func(*os.File, string) error
	validateIdentity func(string) error
}

type lockValidationOperations struct {
	load     func(string) (any, bool)
	lstat    func(*os.Root, string) (os.FileInfo, error)
	open     func(*os.Root, string, string) (*os.File, error)
	validate func(*os.File, os.FileInfo) error
	close    func(*os.File) error
}

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
	return store.acquireAttemptLockWith(
		attemptID,
		directory,
		root,
		create,
		lockAcquisitionOperations{
			reserve: reserveAttemptLock,
			open:    openAttemptLockFile,
			lstat: func(root *os.Root, name string) (os.FileInfo, error) {
				return root.Lstat(name)
			},
			validate:         validateLockFile,
			lock:             lockAttemptFile,
			sync:             syncAttemptLock,
			validateIdentity: store.validateLockIdentity,
		},
	)
}

func (store *Store) acquireAttemptLockWith(
	attemptID,
	directory string,
	root *os.Root,
	create bool,
	operations lockAcquisitionOperations,
) (lock *attemptLock, err error) {
	var reservation *lockReservation
	defer func() {
		lock, err = finishLockRoot(root, reservation, lock, err)
	}()
	name := attemptID + ".lock"
	key := filepath.Join(directory, name)
	reservation, err = operations.reserve(key)
	if err != nil {
		return nil, err
	}
	defer reservation.abandon()
	file, err := operations.open(root, directory, name, create)
	if err != nil {
		return nil, err
	}
	pathInfo, err := operations.lstat(root, name)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("inspect attempt lock: %w", err),
			file.Close(),
		)
	}
	if err := operations.validate(file, pathInfo); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := operations.lock(file); err != nil {
		closeErr := file.Close()
		if errors.Is(err, errLockHeld) {
			return nil, errors.Join(ErrActive, closeErr)
		}
		return nil, errors.Join(fmt.Errorf("lock attempt: %w", err), closeErr)
	}
	if err := operations.sync(file, directory); err != nil {
		return nil, errors.Join(
			fmt.Errorf("sync attempt lock: %w", err),
			unlockAttemptFile(file),
			file.Close(),
		)
	}
	if err := operations.validateIdentity(directory); err != nil {
		return nil, errors.Join(
			err,
			unlockAttemptFile(file),
			file.Close(),
		)
	}
	lock = &attemptLock{file: file, key: key}
	activeAttemptLocks.Store(key, lock)
	reservation.keep = true
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

func (store *Store) validateAttemptLock(attemptID string) (err error) {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	return validateAttemptLockWith(
		root,
		directory,
		attemptID,
		lockValidationOperations{
			load: func(key string) (any, bool) {
				return activeAttemptLocks.Load(key)
			},
			lstat:    func(root *os.Root, name string) (os.FileInfo, error) { return root.Lstat(name) },
			open:     openLockFileReadOnly,
			validate: validateLockFile,
			close:    (*os.File).Close,
		},
	)
}

func validateAttemptLockWith(
	root *os.Root,
	directory,
	attemptID string,
	operations lockValidationOperations,
) (err error) {
	name := attemptID + ".lock"
	key := filepath.Join(directory, name)
	if active, loaded := operations.load(key); loaded {
		owner, ok := active.(*attemptLock)
		if !ok {
			return ErrActive
		}
		pathInfo, err := operations.lstat(root, name)
		if err != nil {
			return ErrCorrupt
		}
		return operations.validate(owner.file, pathInfo)
	}
	file, err := operations.open(root, directory, name)
	if errors.Is(err, os.ErrNotExist) {
		return ErrCorrupt
	}
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, operations.close(file))
	}()
	pathInfo, err := operations.lstat(root, name)
	if err != nil {
		return ErrCorrupt
	}
	return operations.validate(file, pathInfo)
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
	return validateLockFileWith(
		file,
		pathInfo,
		(*os.File).Stat,
		pathIsLinked,
		os.SameFile,
		secureLockFile,
	)
}

func validateLockFileWith(
	file *os.File,
	pathInfo os.FileInfo,
	stat func(*os.File) (os.FileInfo, error),
	linked func(string, os.FileInfo) bool,
	same func(os.FileInfo, os.FileInfo) bool,
	secure func(*os.File, os.FileInfo) error,
) error {
	info, err := stat(file)
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() ||
		linked(file.Name(), pathInfo) ||
		!same(pathInfo, info) ||
		!info.Mode().IsRegular() ||
		info.Size() != 0 {
		return ErrCorrupt
	}
	return secure(file, info)
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
