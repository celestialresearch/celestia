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

func TestRepairInterruptedRecordsReportsOpenFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected repair open failure")
	operations := testRecordRepairOperations()
	operations.openRoot = func(string) (*os.Root, error) {
		return nil, failure
	}
	if err := repairInterruptedRecordsWith(
		t.TempDir(),
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("open-root error = %v", err)
	}

	operations = testRecordRepairOperations()
	operations.openDirectory = func(*os.Root, string) (*os.File, error) {
		return nil, failure
	}
	if err := repairInterruptedRecordsWith(
		t.TempDir(),
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("open-directory error = %v", err)
	}
}

func TestRepairInterruptedRecordsReportsReadFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected repair read failure")
	operations := testRecordRepairOperations()
	operations.readDirectory = func(*os.File) ([]os.DirEntry, error) {
		return nil, failure
	}
	if err := repairInterruptedRecordsWith(
		t.TempDir(),
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("repairInterruptedRecordsWith() error = %v", err)
	}
}

func TestRepairInterruptedRecordsReportsRemoveFailure(t *testing.T) {
	t.Parallel()

	path := protectedTestDirectory(t)
	file, err := createRecordTemp(path, admittedFile)
	if err != nil {
		t.Fatalf("create temporary fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary fixture: %v", err)
	}
	failure := errors.New("injected repair removal failure")
	operations := testRecordRepairOperations()
	operations.remove = func(*os.Root, string) error { return failure }
	if err := repairInterruptedRecordsWith(
		path,
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("repairInterruptedRecordsWith() error = %v", err)
	}
}

func TestRepairInterruptedRecordsHandlesEmptyAndUninspectableEntries(t *testing.T) {
	path := protectedTestDirectory(t)
	operations := testRecordRepairOperations()
	removed := false
	confirmed := false
	operations.readDirectory = func(*os.File) ([]os.DirEntry, error) {
		return []os.DirEntry{}, nil
	}
	operations.remove = func(*os.Root, string) error {
		removed = true
		return nil
	}
	operations.confirm = func(string) error {
		confirmed = true
		return nil
	}
	if err := repairInterruptedRecordsWith(path, operations); err != nil {
		t.Fatalf("empty repair: %v", err)
	}
	if removed || confirmed {
		t.Fatalf("empty repair removed=%t confirmed=%t", removed, confirmed)
	}

	file, err := createRecordTemp(path, admittedFile)
	if err != nil {
		t.Fatalf("create temporary: %v", err)
	}
	name := filepath.Base(file.Name())
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary: %v", err)
	}
	operations = testRecordRepairOperations()
	operations.lstat = func(*os.Root, string) (os.FileInfo, error) {
		return nil, errors.New("injected temporary inspection failure")
	}
	if err := repairInterruptedRecordsWith(path, operations); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("uninspectable %s returned %v", name, err)
	}
}

func testRecordRepairOperations() recordRepairOperations {
	return recordRepairOperations{
		openRoot:  os.OpenRoot,
		closeRoot: (*os.Root).Close,
		openDirectory: func(root *os.Root, name string) (*os.File, error) {
			return root.Open(name)
		},
		readDirectory: func(directory *os.File) ([]os.DirEntry, error) {
			return directory.ReadDir(-1)
		},
		closeFile: (*os.File).Close,
		lstat: func(root *os.Root, name string) (os.FileInfo, error) {
			return root.Lstat(name)
		},
		invalid: invalidRecordFile,
		remove: func(root *os.Root, name string) error {
			return root.Remove(name)
		},
		confirm: confirmPublication,
	}
}
