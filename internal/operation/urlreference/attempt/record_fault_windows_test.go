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
	"testing"

	"golang.org/x/sys/windows"
)

func TestCreateRecordTempReportsFailures(t *testing.T) {
	failure := errors.New("injected record creation failure")
	tests := []struct {
		name    string
		replace func(*recordCreationOperations)
	}{
		{
			name: "descriptor",
			replace: func(operations *recordCreationOperations) {
				operations.descriptor = func() (*windows.SECURITY_DESCRIPTOR, error) {
					return nil, failure
				}
			},
		},
		{
			name: "temporary name",
			replace: func(operations *recordCreationOperations) {
				operations.name = func(string) (string, error) {
					return "", failure
				}
			},
		},
		{
			name: "path encoding",
			replace: func(operations *recordCreationOperations) {
				operations.encode = func(string) (*uint16, error) {
					return nil, failure
				}
			},
		},
		{
			name: "native creation",
			replace: func(operations *recordCreationOperations) {
				operations.create = func(
					*uint16,
					uint32,
					uint32,
					*windows.SecurityAttributes,
					uint32,
					uint32,
					windows.Handle,
				) (windows.Handle, error) {
					return 0, failure
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := recordTestOperations()
			test.replace(&operations)
			if _, err := createRecordTempWith(
				t.TempDir(),
				admittedFile,
				operations,
			); !errors.Is(err, failure) {
				t.Fatalf("createRecordTempWith() error = %v", err)
			}
		})
	}
}

func recordTestOperations() recordCreationOperations {
	return recordCreationOperations{
		descriptor: func() (*windows.SECURITY_DESCRIPTOR, error) {
			return &windows.SECURITY_DESCRIPTOR{}, nil
		},
		name:   func(string) (string, error) { return "record.tmp", nil },
		encode: windows.UTF16PtrFromString,
		create: func(
			*uint16,
			uint32,
			uint32,
			*windows.SecurityAttributes,
			uint32,
			uint32,
			windows.Handle,
		) (windows.Handle, error) {
			return 1, nil
		},
		newFile:     func(uintptr, string) *os.File { return nil },
		closeHandle: func(windows.Handle) error { return nil },
	}
}

func TestCreateRecordTempExhaustsCollisions(t *testing.T) {
	operations := recordCreationOperations{
		descriptor: func() (*windows.SECURITY_DESCRIPTOR, error) {
			return &windows.SECURITY_DESCRIPTOR{}, nil
		},
		name:   func(string) (string, error) { return "record.tmp", nil },
		encode: windows.UTF16PtrFromString,
		create: func(
			*uint16,
			uint32,
			uint32,
			*windows.SecurityAttributes,
			uint32,
			uint32,
			windows.Handle,
		) (windows.Handle, error) {
			return 0, windows.ERROR_FILE_EXISTS
		},
	}
	if _, err := createRecordTempWith(
		t.TempDir(),
		admittedFile,
		operations,
	); err == nil {
		t.Fatal("createRecordTempWith() accepted exhausted collisions")
	}
}

func TestCreateRecordTempClosesUnwrappedHandle(t *testing.T) {
	closed := false
	operations := recordCreationOperations{
		descriptor: func() (*windows.SECURITY_DESCRIPTOR, error) {
			return &windows.SECURITY_DESCRIPTOR{}, nil
		},
		name:   func(string) (string, error) { return "record.tmp", nil },
		encode: windows.UTF16PtrFromString,
		create: func(
			*uint16,
			uint32,
			uint32,
			*windows.SecurityAttributes,
			uint32,
			uint32,
			windows.Handle,
		) (windows.Handle, error) {
			return 7, nil
		},
		newFile: func(uintptr, string) *os.File { return nil },
		closeHandle: func(handle windows.Handle) error {
			closed = handle == 7
			return nil
		},
	}
	if _, err := createRecordTempWith(
		t.TempDir(),
		admittedFile,
		operations,
	); err == nil || !closed {
		t.Fatalf("error = %v, closed = %t", err, closed)
	}
}
