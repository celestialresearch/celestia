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

func TestPrepareEvidenceRootReportsBoundaryFailures(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "evidence")
	failure := errors.New("injected evidence-root failure")
	existingInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat existing path: %v", err)
	}
	baseLstat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	tests := []struct {
		name        string
		resolve     func(string) (string, error)
		rejectLinks func(string) error
		lstat       func(string) (os.FileInfo, error)
		adopt       func(string) error
		create      func(string) error
	}{
		{
			name: "resolve",
			resolve: func(string) (string, error) {
				return "", failure
			},
		},
		{
			name:        "linked ancestor",
			rejectLinks: func(string) error { return failure },
		},
		{
			name: "inspect",
			lstat: func(string) (os.FileInfo, error) {
				return nil, failure
			},
		},
		{
			name: "adopt",
			lstat: func(string) (os.FileInfo, error) {
				return existingInfo, nil
			},
			adopt: func(string) error { return failure },
		},
		{
			name:   "create",
			create: func(string) error { return failure },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolve := test.resolve
			if resolve == nil {
				resolve = func(string) (string, error) { return root, nil }
			}
			rejectLinks := test.rejectLinks
			if rejectLinks == nil {
				rejectLinks = func(string) error { return nil }
			}
			lstat := test.lstat
			if lstat == nil {
				lstat = baseLstat
			}
			adopt := test.adopt
			if adopt == nil {
				adopt = func(string) error { return nil }
			}
			create := test.create
			if create == nil {
				create = func(string) error { return nil }
			}
			_, err := prepareEvidenceRootWith(
				root, resolve, rejectLinks, lstat, adopt, create,
			)
			if !errors.Is(err, failure) {
				t.Fatalf("prepareEvidenceRootWith() error = %v", err)
			}
		})
	}
}

func TestCreateEvidenceRootReportsBoundaryFailures(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	path := filepath.Join(parent, "evidence")
	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	failure := errors.New("injected evidence-root creation failure")

	tests := []struct {
		name         string
		lstat        func(string) (os.FileInfo, error)
		secureParent func(string) error
		create       func(string) error
	}{
		{
			name: "inspect",
			lstat: func(string) (os.FileInfo, error) {
				return nil, failure
			},
		},
		{
			name: "non-directory",
			lstat: func(string) (os.FileInfo, error) {
				return fileInfo, nil
			},
		},
		{
			name:         "secure parent",
			secureParent: func(string) error { return failure },
		},
		{
			name:   "create",
			create: func(string) error { return failure },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lstat := test.lstat
			if lstat == nil {
				lstat = func(string) (os.FileInfo, error) {
					return parentInfo, nil
				}
			}
			secureParent := test.secureParent
			if secureParent == nil {
				secureParent = func(string) error { return nil }
			}
			create := test.create
			if create == nil {
				create = func(string) error { return nil }
			}
			err := createEvidenceRootWith(path, lstat, secureParent, create)
			if test.name == "non-directory" {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("non-directory error = %v", err)
				}
			} else if !errors.Is(err, failure) {
				t.Fatalf("%s error = %v", test.name, err)
			}
		})
	}
}

func TestEvidenceDirectoryHelpersReportFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("injected evidence-directory failure")
	existingInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat existing directory: %v", err)
	}
	if err := prepareEvidenceDirectoriesWith(
		t.TempDir(),
		func(string) error { return failure },
	); !errors.Is(err, failure) {
		t.Fatalf("prepare directories error = %v", err)
	}
	if err := validateEvidenceDirectoriesWith(
		t.TempDir(),
		func(string) error { return failure },
	); !errors.Is(err, failure) {
		t.Fatalf("validate directories error = %v", err)
	}
	if err := ensureEvidenceDirectoryWith(
		"unused",
		func(string) (os.FileInfo, error) { return nil, failure },
		func(string) error { return nil },
		func(string) error { return nil },
	); !errors.Is(err, failure) {
		t.Fatalf("ensure inspect error = %v", err)
	}
	if err := ensureEvidenceDirectoryWith(
		"unused",
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(string) error { return failure },
		func(string) error { return nil },
	); !errors.Is(err, failure) {
		t.Fatalf("ensure create error = %v", err)
	}
	if err := ensureEvidenceDirectoryWith(
		"unused",
		func(string) (os.FileInfo, error) { return existingInfo, nil },
		func(string) error { return nil },
		func(string) error { return failure },
	); !errors.Is(err, failure) {
		t.Fatalf("ensure secure error = %v", err)
	}
	if _, err := createLockDirectoryWith(
		t.TempDir(),
		func(string) error { return failure },
	); !errors.Is(err, failure) {
		t.Fatalf("create lock directory error = %v", err)
	}
}
