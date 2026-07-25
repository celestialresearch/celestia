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

	"golang.org/x/sys/windows"
)

func TestPublishFileRejectsInvalidPaths(t *testing.T) {
	if err := publishFile("invalid\x00source", "target", t.TempDir()); err == nil {
		t.Fatal("invalid source path accepted")
	}
	if err := publishFile("source", "invalid\x00target", t.TempDir()); err == nil {
		t.Fatal("invalid target path accepted")
	}
}

func TestNewSetsWindowsOwnerDACL(t *testing.T) {
	store := newTestStore(t)
	descriptor, err := windows.GetNamedSecurityInfo(
		store.root,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read security descriptor: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read DACL: %v", err)
	}
	if dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("unexpected DACL entries: %#v", dacl)
	}
}

func TestWindowsSecurityHelpersRejectFilesAndInvalidPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("file"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := secureEvidenceTree(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("file secured as evidence directory: %v", err)
	}
	if !pathIsLinked("invalid\x00path", nil) {
		t.Fatal("invalid path treated as safe")
	}
	if err := secureEvidenceTree(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory secured: %v", err)
	}
}
