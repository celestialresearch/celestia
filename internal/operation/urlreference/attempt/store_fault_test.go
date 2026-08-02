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

func TestNewStoreReportsConstructionFailures(t *testing.T) {
	failure := errors.New("injected store construction failure")
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	base := func() storeCreationOperations {
		return storeCreationOperations{
			prepareRoot:        func(string) (string, error) { return `C:\evidence`, nil },
			prepareDirectories: func(string) error { return nil },
			createLock:         func(string) (bool, error) { return false, nil },
			validateDirectories: func(string) error {
				return nil
			},
			syncLocks: func(string) error { return nil },
			lstat: func(string) (os.FileInfo, error) {
				return info, nil
			},
		}
	}
	tests := []struct {
		name    string
		replace func(*storeCreationOperations)
	}{
		{
			name: "prepare root",
			replace: func(operations *storeCreationOperations) {
				operations.prepareRoot = func(string) (string, error) {
					return "", failure
				}
			},
		},
		{
			name: "prepare directories",
			replace: func(operations *storeCreationOperations) {
				operations.prepareDirectories = func(string) error { return failure }
			},
		},
		{
			name: "create lock directory",
			replace: func(operations *storeCreationOperations) {
				operations.createLock = func(string) (bool, error) {
					return false, failure
				}
			},
		},
		{
			name: "validate directories",
			replace: func(operations *storeCreationOperations) {
				operations.validateDirectories = func(string) error { return failure }
			},
		},
		{
			name: "sync lock directory",
			replace: func(operations *storeCreationOperations) {
				operations.createLock = func(string) (bool, error) { return true, nil }
				operations.syncLocks = func(string) error { return failure }
			},
		},
		{
			name: "inspect lock directory",
			replace: func(operations *storeCreationOperations) {
				operations.lstat = func(string) (os.FileInfo, error) {
					return nil, failure
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := base()
			test.replace(&operations)
			if _, err := newStoreWith("root", operations); !errors.Is(err, failure) {
				t.Fatalf("newStoreWith() error = %v", err)
			}
		})
	}
}

func protectedTestDirectory(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "owned")
	if err := createEvidenceDirectory(parent); err != nil {
		t.Fatalf("create protected parent: %v", err)
	}
	path := filepath.Join(parent, "records")
	if err := createEvidenceDirectory(path); err != nil {
		t.Fatalf("create protected records: %v", err)
	}
	return path
}
