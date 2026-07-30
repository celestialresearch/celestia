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
	"testing"
)

func TestCreateOwnershipMarkerReportsOwnedFailures(t *testing.T) {
	failure := errors.New("injected ownership creation failure")
	tests := []struct {
		name    string
		replace func(*ownershipCreationOperations)
		created bool
	}{
		{
			name: "open",
			replace: func(operations *ownershipCreationOperations) {
				operations.open = func(
					*os.Root, string, string, bool,
				) (*os.File, error) {
					return nil, failure
				}
			},
		},
		{
			name: "secure",
			replace: func(operations *ownershipCreationOperations) {
				operations.secure = func(*os.File, os.FileInfo) error {
					return failure
				}
			},
			created: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			accepted, _ := testAccepted(t)
			directory := filepath.Join(store.root, locksDirectory)
			root, err := store.openLockRoot(directory)
			if err != nil {
				t.Fatalf("open lock root: %v", err)
			}
			operations := testOwnershipCreationOperations()
			test.replace(&operations)
			created, err := createOwnershipMarkerWith(
				root,
				directory,
				accepted.Request.AttemptID,
				operations,
			)
			closeErr := root.Close()
			if created != test.created || !errors.Is(err, failure) ||
				closeErr != nil {
				t.Fatalf(
					"created = %t, error = %v, close = %v",
					created,
					err,
					closeErr,
				)
			}
		})
	}
}

func testOwnershipCreationOperations() ownershipCreationOperations {
	return ownershipCreationOperations{
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
	}
}

func TestHasOwnershipMarkerReportsOpenFailure(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	if err := store.createOwnershipMarker(attemptID); err != nil {
		t.Fatalf("create marker fixture: %v", err)
	}
	directory := filepath.Join(store.root, locksDirectory)
	root, err := store.openLockRoot(directory)
	if err != nil {
		t.Fatalf("open lock root: %v", err)
	}
	failure := errors.New("injected ownership open failure")
	_, err = hasOwnershipMarkerWith(
		root,
		directory,
		attemptID,
		ownershipInspectionOperations{
			lstat: func(root *os.Root, name string) (os.FileInfo, error) {
				return root.Lstat(name)
			},
			linked: pathIsLinked,
			open: func(*os.Root, string, string) (*os.File, error) {
				return nil, failure
			},
			validate: validateLockFile,
			close:    (*os.File).Close,
		},
	)
	closeErr := root.Close()
	if !errors.Is(err, failure) || closeErr != nil {
		t.Fatalf("error = %v, close = %v", err, closeErr)
	}
}

func TestValidateAttemptLockReportsInspectionRace(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	directory := filepath.Join(store.root, locksDirectory)
	file, err := openAttemptLockFile(
		nil,
		directory,
		attemptID+".lock",
		true,
	)
	if err != nil {
		t.Fatalf("create lock fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close lock fixture: %v", err)
	}
	root, err := store.openLockRoot(directory)
	if err != nil {
		t.Fatalf("open lock root: %v", err)
	}
	err = validateAttemptLockWith(
		root,
		directory,
		attemptID,
		lockValidationOperations{
			load: func(string) (any, bool) { return nil, false },
			lstat: func(*os.Root, string) (os.FileInfo, error) {
				return nil, errors.New("injected inspection failure")
			},
			open:     openLockFileReadOnly,
			validate: validateLockFile,
			close:    (*os.File).Close,
		},
	)
	closeErr := root.Close()
	if !errors.Is(err, ErrCorrupt) || closeErr != nil {
		t.Fatalf("error = %v, close = %v", err, closeErr)
	}
}

func TestOpenLockRootReportsOwnedFailures(t *testing.T) {
	failure := errors.New("injected lock-root failure")
	tests := []struct {
		name    string
		replace func(*lockRootOperations)
		want    error
	}{
		{
			name: "ancestor inspection",
			replace: func(operations *lockRootOperations) {
				operations.ancestors = func(string) error { return failure }
			},
			want: failure,
		},
		{
			name: "root open",
			replace: func(operations *lockRootOperations) {
				operations.open = func(string) (*os.Root, error) {
					return nil, failure
				}
			},
			want: failure,
		},
		{
			name: "root identity",
			replace: func(operations *lockRootOperations) {
				operations.stat = func(
					*os.Root,
					string,
				) (os.FileInfo, error) {
					return nil, failure
				}
			},
			want: ErrCorrupt,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			directory := filepath.Join(store.root, locksDirectory)
			operations := lockRootOperations{
				ancestors: rejectLinkedAncestors,
				identity:  store.validateLockIdentity,
				open:      os.OpenRoot,
				stat: func(root *os.Root, name string) (os.FileInfo, error) {
					return root.Stat(name)
				},
			}
			test.replace(&operations)
			root, err := openLockRootWith(
				directory,
				operations,
				store.lockIdentity,
			)
			if root != nil || !errors.Is(err, test.want) {
				t.Fatalf("root = %v, error = %v", root, err)
			}
		})
	}
}
