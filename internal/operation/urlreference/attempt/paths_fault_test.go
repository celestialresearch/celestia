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

func TestCanonicalEvidenceRootReportsAncestorFailure(t *testing.T) {
	t.Parallel()
	failure := errors.New("injected ancestor failure")
	calls := 0
	_, err := canonicalEvidenceRootWith(
		filepath.Join(t.TempDir(), "missing"),
		func(string) (os.FileInfo, error) {
			calls++
			if calls == 1 {
				return nil, os.ErrNotExist
			}
			return nil, failure
		},
		func(string) (string, error) { return "", nil },
	)
	if !errors.Is(err, failure) {
		t.Fatalf("canonicalEvidenceRootWith() error = %v", err)
	}
}

func TestCanonicalEvidenceRootRejectsMissingFilesystemRoot(t *testing.T) {
	t.Parallel()
	_, err := canonicalEvidenceRootWith(
		filepath.Join(t.TempDir(), "missing"),
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(string) (string, error) { return "", nil },
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonicalEvidenceRootWith() error = %v", err)
	}
}

func TestPathExistsReportsInspectionAndLinkFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("injected path inspection failure")
	if _, err := pathExistsWith(
		"path",
		func(string) error { return nil },
		func(string) (os.FileInfo, error) { return nil, failure },
		func(string, os.FileInfo) bool { return false },
	); !errors.Is(err, failure) {
		t.Fatalf("path inspection error = %v", err)
	}
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	if _, err := pathExistsWith(
		"path",
		func(string) error { return nil },
		func(string) (os.FileInfo, error) { return info, nil },
		func(string, os.FileInfo) bool { return true },
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked path error = %v", err)
	}
	if _, err := pathExistsWith(
		"path",
		func(string) error { return nil },
		func(string) (os.FileInfo, error) {
			return modeFileInfo{FileInfo: info, mode: os.ModeSymlink}, nil
		},
		func(string, os.FileInfo) bool {
			t.Fatal("linked check reached after symlink mode")
			return false
		},
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("symlink path error = %v", err)
	}
}

type modeFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info modeFileInfo) Mode() os.FileMode {
	return info.mode
}
