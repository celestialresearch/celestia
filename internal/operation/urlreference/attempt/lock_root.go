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
)

type lockRootOperations struct {
	ancestors func(string) error
	identity  func(string) error
	open      func(string) (*os.Root, error)
	stat      func(*os.Root, string) (os.FileInfo, error)
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
