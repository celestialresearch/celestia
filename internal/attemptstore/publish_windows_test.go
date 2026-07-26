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

func TestPublishFileRejectsDuplicate(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	for _, path := range []string{source, target} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", filepath.Base(path), err)
		}
	}
	if err := publishFile(source, target, root); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate target accepted: %v", err)
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

func TestNewRejectsUnmanagedWindowsParent(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "evidence")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unmanaged parent accepted: %v", err)
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
	if err := secureEvidenceFile(filepath.Join(t.TempDir(), "missing-file")); err == nil {
		t.Fatal("missing evidence file secured")
	}
}

func TestRecordTempRejectsMissingDirectory(t *testing.T) {
	store := newTestStore(t)
	temporary, err := createRecordTemp(store.root, "record.json")
	if err != nil {
		t.Fatalf("create protected record temporary file: %v", err)
	}
	name := temporary.Name()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := temporary.Close(); err != nil {
		t.Fatalf("close protected record temporary file: %v", err)
	}
	if err := secureEvidenceFile(name); err != nil {
		t.Fatalf("protected record temporary file rejected: %v", err)
	}
	_, err = createRecordTemp(filepath.Join(t.TempDir(), "missing"), "record.json")
	if err == nil {
		t.Fatal("record temporary file created in a missing directory")
	}
	if _, err := createRecordTemp("invalid\x00path", "record.json"); err == nil {
		t.Fatal("record temporary file accepted an invalid path")
	}
	if err := createEvidenceDirectory(t.TempDir()); err == nil {
		t.Fatal("existing evidence directory recreated")
	}
}

func TestWindowsSecurityHelpersRejectInvalidPaths(t *testing.T) {
	if err := secureEvidenceTree("invalid\x00path"); err == nil {
		t.Fatal("invalid evidence tree path accepted")
	}
	if err := secureOwnedPath("invalid\x00path"); err == nil {
		t.Fatal("invalid ownership path accepted")
	}
	if err := secureOwnedPath(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing ownership path accepted")
	}
	if err := secureDirectoryACL("invalid\x00path"); err == nil {
		t.Fatal("invalid ACL path accepted")
	}
	if err := secureDirectoryACL(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing ACL path accepted")
	}
	if err := secureEvidenceFile("invalid\x00path"); err == nil {
		t.Fatal("invalid evidence file path accepted")
	}
	if err := createEvidenceDirectory("invalid\x00path"); err == nil {
		t.Fatal("invalid evidence directory path accepted")
	}
	if !pathIsLinked(filepath.Join(t.TempDir(), "missing"), nil) {
		t.Fatal("missing Windows path treated as unlinked")
	}
}

func TestWindowsSecurityHelpersRejectUnmanagedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unmanaged")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create unmanaged directory: %v", err)
	}
	if err := secureEvidenceTree(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unmanaged directory accepted: %v", err)
	}
}

func TestWindowsSecurityHelpersRejectReadOnlyDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read-only")
	if err := createEvidenceDirectory(path); err != nil {
		t.Fatalf("create evidence directory: %v", err)
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FR;;;%s)", sid, sid),
	)
	if err != nil {
		t.Fatalf("create read-only descriptor: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read descriptor DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("apply read-only DACL: %v", err)
	}
	if _, err := New(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("read-only evidence root accepted: %v", err)
	}
}
