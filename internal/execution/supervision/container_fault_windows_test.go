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

//go:build windows && amd64

package supervision

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestContainerCreateNativeFailures(t *testing.T) {
	tests := []struct {
		name   string
		result uintptr
		call   error
		want   string
	}{
		{name: "duplicate", result: uintptr(errAppContainerAlreadyExists), want: "duplicate"},
		{name: "unavailable", result: 1, call: windows.ERROR_PROC_NOT_FOUND, want: "unavailable"},
		{name: "HRESULT", result: 5, want: "HRESULT"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := completeContainerCreation(
				"test",
				nil,
				nativeCallResult{code: test.result, err: test.call},
				func(*windows.SID) (string, error) {
					t.Fatal("folder lookup called")
					return "", nil
				},
				func(*appContainer) error {
					t.Fatal("rollback called")
					return nil
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestContainerCreateMissingSID(t *testing.T) {
	rollbackErr := errors.New("rollback")
	for _, test := range []struct {
		name     string
		rollback error
	}{
		{name: "rollback succeeds"},
		{name: "rollback fails", rollback: rollbackErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			rolledBack := false
			_, err := completeContainerCreation(
				"test",
				nil,
				nativeCallResult{},
				func(*windows.SID) (string, error) {
					t.Fatal("folder lookup called")
					return "", nil
				},
				func(*appContainer) error {
					rolledBack = true
					return test.rollback
				},
			)
			if err == nil || !rolledBack || !strings.Contains(err.Error(), "missing SID") {
				t.Fatalf("rolledBack=%t error=%v", rolledBack, err)
			}
			if test.rollback != nil && !errors.Is(err, test.rollback) {
				t.Fatalf("rollback error lost: %v", err)
			}
		})
	}
}

func TestContainerCreateFolderStates(t *testing.T) {
	sid := new(windows.SID)
	folderErr := errors.New("folder")
	rollbackErr := errors.New("rollback")
	for _, test := range []struct {
		name     string
		rollback error
	}{
		{name: "rollback succeeds"},
		{name: "rollback fails", rollback: rollbackErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			rolledBack := false
			_, err := completeContainerCreation(
				"test",
				sid,
				nativeCallResult{},
				func(*windows.SID) (string, error) { return "", folderErr },
				func(*appContainer) error {
					rolledBack = true
					return test.rollback
				},
			)
			if !errors.Is(err, folderErr) || !rolledBack {
				t.Fatalf("rolledBack=%t error=%v", rolledBack, err)
			}
			if test.rollback != nil && !errors.Is(err, test.rollback) {
				t.Fatalf("rollback error lost: %v", err)
			}
		})
	}
	container, err := completeContainerCreation(
		"test",
		sid,
		nativeCallResult{},
		func(got *windows.SID) (string, error) {
			if got != sid {
				t.Fatal("SID changed")
			}
			return `C:\container`, nil
		},
		func(*appContainer) error {
			t.Fatal("rollback called")
			return nil
		},
	)
	if err != nil || container.sid != sid || container.folder != `C:\container` {
		t.Fatalf("container=%+v error=%v", container, err)
	}
}

func TestContainerDeletionNativeStates(t *testing.T) {
	callErr := errors.New("delete")
	if err := completeContainerDeletion(0, nil); err != nil {
		t.Fatalf("successful deletion: %v", err)
	}
	if err := completeContainerDeletion(5, callErr); !errors.Is(err, callErr) {
		t.Fatalf("deletion call error = %v", err)
	}
	if err := completeContainerDeletion(5, nil); err == nil ||
		!strings.Contains(err.Error(), "HRESULT") {
		t.Fatalf("deletion result error = %v", err)
	}
	err := completeContainerDeletion(5, windows.ERROR_SUCCESS)
	if err == nil || !strings.Contains(err.Error(), "HRESULT") {
		t.Fatalf("deletion HRESULT error = %v", err)
	}
}

func TestContainerFolderNativeStates(t *testing.T) {
	testContainerFolderFailures(t)
	testContainerFolderSuccess(t)
}

func testContainerFolderFailures(t *testing.T) {
	t.Helper()
	for _, test := range []struct {
		name   string
		result uintptr
		call   error
		want   string
	}{
		{name: "unavailable", result: 1, call: windows.ERROR_PROC_NOT_FOUND, want: "unavailable"},
		{name: "HRESULT", result: 5, want: "HRESULT"},
		{name: "missing path", want: "missing path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := completeContainerFolder(
				nil,
				nativeCallResult{code: test.result, err: test.call},
				func() { t.Fatal("free called") },
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func testContainerFolderSuccess(t *testing.T) {
	t.Helper()
	encoded, err := windows.UTF16FromString(`C:\container`)
	if err != nil {
		t.Fatalf("encode folder: %v", err)
	}
	freed := false
	folder, err := completeContainerFolder(
		&encoded[0],
		nativeCallResult{},
		func() {
			freed = true
		},
	)
	if err != nil || folder != `C:\container` || !freed {
		t.Fatalf("folder=%q freed=%t error=%v", folder, freed, err)
	}
}
