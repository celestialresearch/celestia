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

//go:build windows || (linux && amd64)

package attemptstore

import (
	"fmt"
	"os"
	"path/filepath"
)

type Store struct {
	root         string
	lockIdentity os.FileInfo
}

type storeCreationOperations struct {
	prepareRoot         func(string) (string, error)
	prepareDirectories  func(string) error
	createLock          func(string) (bool, error)
	validateDirectories func(string) error
	syncLocks           func(string) error
	lstat               func(string) (os.FileInfo, error)
}

func New(root string) (*Store, error) {
	return newStoreWith(root, storeCreationOperations{
		prepareRoot:         prepareEvidenceRoot,
		prepareDirectories:  prepareEvidenceDirectories,
		createLock:          createLockDirectory,
		validateDirectories: validateEvidenceDirectories,
		syncLocks:           syncAttemptLockDirectory,
		lstat:               lstatEvidencePath,
	})
}

func newStoreWith(
	root string,
	operations storeCreationOperations,
) (*Store, error) {
	clean, err := operations.prepareRoot(root)
	if err != nil {
		return nil, err
	}
	if err := operations.prepareDirectories(clean); err != nil {
		return nil, err
	}
	lockDirectoryCreated, err := operations.createLock(clean)
	if err != nil {
		return nil, fmt.Errorf("create attempt locks: %w", err)
	}
	if err := operations.validateDirectories(clean); err != nil {
		return nil, err
	}
	if lockDirectoryCreated {
		if err := operations.syncLocks(clean); err != nil {
			return nil, fmt.Errorf("sync attempt locks: %w", err)
		}
	}
	lockIdentity, err := operations.lstat(filepath.Join(clean, locksDirectory))
	if err != nil {
		return nil, fmt.Errorf("inspect attempt locks: %w", err)
	}
	return &Store{root: clean, lockIdentity: lockIdentity}, nil
}
