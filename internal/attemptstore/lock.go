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
	file, err := openAttemptLockFile(root, directory, name, create)
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

func (store *Store) createOwnershipMarker(attemptID string) error {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
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

func (store *Store) prepareOwnershipMarker(attemptID string) error {
	present, err := store.hasOwnershipMarker(attemptID)
	if err != nil {
		return err
	}
	if !present {
		return store.createOwnershipMarker(attemptID)
	}
	for _, path := range []string{
		store.pendingPath(attemptID),
		store.finalPath(attemptID),
	} {
		exists, err := pathExists(path)
		if err != nil {
			return fmt.Errorf("inspect marker-owned attempt: %w", err)
		}
		if exists {
			return ErrDuplicate
		}
	}
	if err := store.removeOwnershipMarker(attemptID); err != nil {
		return err
	}
	return store.createOwnershipMarker(attemptID)
}

func (store *Store) hasOwnershipMarker(attemptID string) (bool, error) {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = root.Close()
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
		_ = file.Close()
	}()
	if err := validateLockFile(file, pathInfo); err != nil {
		return false, err
	}
	return true, nil
}

func (store *Store) removeOwnershipMarker(attemptID string) error {
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()
	name := attemptID + ownershipMarkerSuffix
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("remove attempt ownership marker: %w", err)
	}
	if err := syncAttemptLockDirectory(directory); err != nil {
		return fmt.Errorf("sync attempt ownership marker removal: %w", err)
	}
	return nil
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
