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

type lockAcquisitionOperations struct {
	reserve          func(string) (*lockReservation, error)
	open             func(*os.Root, string, string, bool) (*os.File, error)
	lstat            func(*os.Root, string) (os.FileInfo, error)
	validate         func(*os.File, os.FileInfo) error
	lock             func(*os.File) error
	sync             func(*os.File, string) error
	validateIdentity func(string) error
}

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

type lockValidationOperations struct {
	load     func(string) (any, bool)
	lstat    func(*os.Root, string) (os.FileInfo, error)
	open     func(*os.Root, string, string) (*os.File, error)
	validate func(*os.File, os.FileInfo) error
	close    func(*os.File) error
}

type lockRootOperations struct {
	ancestors func(string) error
	identity  func(string) error
	open      func(string) (*os.Root, error)
	stat      func(*os.Root, string) (os.FileInfo, error)
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

func (store *Store) openLockRoot(directory string) (*os.Root, error) {
	return openLockRootWith(
		directory,
		lockRootOperations{
			ancestors: rejectLinkedAncestors,
			identity:  store.validateLockIdentity,
			open:      os.OpenRoot,
			stat: func(root *os.Root, name string) (os.FileInfo, error) {
				return root.Stat(name)
			},
		},
		store.lockIdentity,
	)
}

func openLockRootWith(
	directory string,
	operations lockRootOperations,
	expected os.FileInfo,
) (*os.Root, error) {
	if err := operations.ancestors(directory); err != nil {
		return nil, fmt.Errorf("inspect attempt locks: %w", err)
	}
	if err := operations.identity(directory); err != nil {
		return nil, err
	}
	root, err := operations.open(directory)
	if err != nil {
		return nil, fmt.Errorf("open attempt locks: %w", err)
	}
	rootInfo, err := operations.stat(root, ".")
	if err != nil || !os.SameFile(expected, rootInfo) {
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
