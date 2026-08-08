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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireAttemptLockRejectsInvalidState(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.acquireAttemptLock("invalid", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid identity error = %v", err)
	}
	accepted, _ := testAccepted(t)
	if _, err := store.acquireAttemptLock(
		accepted.Request.AttemptID,
		false,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing lock error = %v", err)
	}
}

func TestLockOperationsRejectReplacedDirectory(t *testing.T) {
	store := newTestStore(t)
	directory := filepath.Join(store.root, locksDirectory)
	displaced := directory + ".displaced"
	if err := os.Rename(directory, displaced); err != nil {
		t.Fatalf("displace locks directory: %v", err)
	}
	if err := createEvidenceDirectory(directory); err != nil {
		t.Fatalf("replace locks directory: %v", err)
	}
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	for name, operation := range map[string]func() error{
		"acquire": func() error {
			_, err := store.acquireAttemptLock(attemptID, true)
			return err
		},
		"create marker": func() error {
			_, err := store.createOwnershipMarkerState(attemptID)
			return err
		},
		"find marker": func() error {
			_, err := store.hasOwnershipMarker(attemptID)
			return err
		},
		"validate": func() error {
			return store.validateAttemptLock(attemptID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v, want %v", err, ErrCorrupt)
			}
		})
	}
}

func TestLockHelpersRejectClosedFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatalf("create lock: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close lock: %v", err)
	}
	if err := syncAttemptLock(file, t.TempDir()); err == nil {
		t.Fatal("closed lock synchronised")
	}
	if err := validateLockFile(file, info); err == nil {
		t.Fatal("closed lock validated")
	}
}

func TestFinishLockRootWithoutLock(t *testing.T) {
	closeErr := errors.New("close root")
	lock, err := finishLockRootResult(closeErr, nil, nil, nil)
	if lock != nil || !errors.Is(err, closeErr) {
		t.Fatalf("lock = %v, error = %v", lock, err)
	}
}

func TestValidateLockIdentityRejectsMissingDirectory(t *testing.T) {
	store := newTestStore(t)
	directory := filepath.Join(store.root, locksDirectory)
	if err := os.Remove(directory); err != nil {
		t.Fatalf("remove locks directory: %v", err)
	}
	if err := store.validateLockIdentity(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want %v", err, ErrCorrupt)
	}
}

func TestLockMetadataRejectsInvalidIdentity(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	invalid := "invalid\x00identity"
	if _, err := store.createOwnershipMarkerState(invalid); err == nil {
		t.Fatal("createOwnershipMarkerState() accepted an embedded NUL")
	}
	if _, err := store.hasOwnershipMarker(invalid); err == nil {
		t.Fatal("hasOwnershipMarker() accepted an embedded NUL")
	}
	if err := store.validateAttemptLock(invalid); err == nil {
		t.Fatal("validateAttemptLock() accepted an embedded NUL")
	}
}

func TestLockFileRejectsObjectMismatch(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatalf("create lock: %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close lock: %v", err)
		}
	})
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	directoryInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	tests := map[string]struct {
		pathInfo os.FileInfo
		statInfo os.FileInfo
		linked   bool
		same     bool
	}{
		"non-regular path": {pathInfo: directoryInfo, statInfo: info, same: true},
		"linked path":      {pathInfo: info, statInfo: info, linked: true, same: true},
		"replaced object":  {pathInfo: info, statInfo: info},
		"non-regular handle": {
			pathInfo: info,
			statInfo: directoryInfo,
			same:     true,
		},
		"non-empty handle": {
			pathInfo: info,
			statInfo: overriddenFileInfo{FileInfo: info, size: 1},
			same:     true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateLockFileWith(
				file,
				test.pathInfo,
				func(*os.File) (os.FileInfo, error) { return test.statInfo, nil },
				func(string, os.FileInfo) bool { return test.linked },
				func(os.FileInfo, os.FileInfo) bool { return test.same },
				func(*os.File, os.FileInfo) error { return nil },
			)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid lock object accepted: %v", err)
			}
		})
	}
}

func TestLockReleaseCloseFailureRetainsReservation(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatalf("create lock: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close lock fixture: %v", err)
	}
	key := "release-close-failure-" + time.Now().UTC().Format(time.RFC3339Nano)
	lock := &attemptLock{file: file, key: key}
	activeAttemptLocks.Store(key, lock)
	t.Cleanup(func() { activeAttemptLocks.Delete(key) })

	first := lock.release()
	second := lock.release()
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("release errors = (%v, %v)", first, second)
	}
	if _, loaded := activeAttemptLocks.Load(key); !loaded {
		t.Fatal("failed close released active reservation")
	}
	if _, err := reserveAttemptLock(key); !errors.Is(err, ErrActive) {
		t.Fatalf("second reservation error = %v, want %v", err, ErrActive)
	}
}

type overriddenFileInfo struct {
	os.FileInfo
	size int64
}

func (info overriddenFileInfo) Size() int64 {
	if info.size != 0 {
		return info.size
	}
	return info.FileInfo.Size()
}

func TestAcquireAttemptLockReportsOwnedFailures(t *testing.T) {
	failure := errors.New("injected acquisition failure")
	tests := []struct {
		name    string
		replace func(*lockAcquisitionOperations)
	}{
		{
			name: "path inspection",
			replace: func(operations *lockAcquisitionOperations) {
				operations.lstat = func(*os.Root, string) (os.FileInfo, error) {
					return nil, failure
				}
			},
		},
		{
			name: "native lock",
			replace: func(operations *lockAcquisitionOperations) {
				operations.lock = func(*os.File) error { return failure }
			},
		},
		{
			name: "synchronisation",
			replace: func(operations *lockAcquisitionOperations) {
				operations.sync = func(*os.File, string) error { return failure }
			},
		},
		{
			name: "identity revalidation",
			replace: func(operations *lockAcquisitionOperations) {
				operations.validateIdentity = func(string) error { return failure }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			accepted, _ := testAccepted(t)
			attemptID := accepted.Request.AttemptID
			directory := filepath.Join(store.root, locksDirectory)
			root, err := store.openLockRoot(directory)
			if err != nil {
				t.Fatalf("open lock root: %v", err)
			}
			operations := testLockAcquisitionOperations(store)
			test.replace(&operations)
			lock, err := store.acquireAttemptLockWith(
				attemptID,
				directory,
				root,
				true,
				operations,
			)
			if lock != nil || !errors.Is(err, failure) {
				t.Fatalf("lock = %v, error = %v", lock, err)
			}
			key := filepath.Join(directory, attemptID+".lock")
			if _, active := activeAttemptLocks.Load(key); active {
				t.Fatal("failed acquisition retained an active reservation")
			}
		})
	}
}

func testLockAcquisitionOperations(store *Store) lockAcquisitionOperations {
	return lockAcquisitionOperations{
		reserve: reserveAttemptLock,
		open:    openAttemptLockFile,
		lstat: func(root *os.Root, name string) (os.FileInfo, error) {
			return root.Lstat(name)
		},
		validate:         validateLockFile,
		lock:             lockAttemptFile,
		sync:             syncAttemptLock,
		validateIdentity: store.validateLockIdentity,
	}
}
