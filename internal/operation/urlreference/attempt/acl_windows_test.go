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
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestEvidenceACERejectsInvalidSID(t *testing.T) {
	t.Parallel()

	expected, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID() error = %v", err)
	}
	ace := windows.ACCESS_ALLOWED_ACE{}
	ace.Header.AceSize = uint16(unsafe.Offsetof(ace.SidStart) + 8)
	if evidenceACEIdentifies(&ace, expected) {
		t.Fatal("invalid SID accepted")
	}
}

func TestEvidenceACERejectsTruncatedSID(t *testing.T) {
	userSID, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID() error = %v", err)
	}
	ace := windows.ACCESS_ALLOWED_ACE{}
	ace.Header.AceSize = uint16(unsafe.Offsetof(ace.SidStart) + 7)
	if evidenceACEIdentifies(&ace, userSID) {
		t.Fatal("truncated ACE accepted")
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("D:P(A;;FA;;;%s)", userSID),
	)
	if err != nil {
		t.Fatalf("create descriptor: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read DACL: %v", err)
	}
	var mismatched *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &mismatched); err != nil {
		t.Fatalf("read ACE: %v", err)
	}
	mismatched.Header.AceSize++
	if evidenceACEIdentifies(mismatched, userSID) {
		t.Fatal("ACE size mismatch accepted")
	}
}

func TestRemoveCreatedDirectoryRemovesOnlyOwnedDirectory(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "created")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create owned directory: %v", err)
	}
	if err := removeCreatedDirectory(path, parent); err != nil {
		t.Fatalf("remove created directory: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created directory remains: %v", err)
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() {
		t.Fatalf("parent changed: info=%v error=%v", info, err)
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

func TestSecureEvidenceFileRejectsReadOnlyDACL(t *testing.T) {
	store := newTestStore(t)
	file, err := createRecordTemp(store.root, "record.json")
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("close record: %v", err)
	}
	t.Cleanup(func() { removeTestPath(t, path) })
	setReadOnlyDACL(t, path)
	if err := secureEvidenceFile(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("read-only evidence file accepted: %v", err)
	}
}

func setReadOnlyDACL(t *testing.T, path string) {
	t.Helper()

	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	setDACL(t, path, fmt.Sprintf("O:%sD:P(A;OICI;FR;;;%s)", sid, sid))
}

func setSharedDACL(t *testing.T, path string) {
	t.Helper()

	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	setDACL(
		t,
		path,
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FR;;;WD)", sid, sid),
	)
}

func setDACL(t *testing.T, path, value string) {
	t.Helper()

	descriptor, err := windows.SecurityDescriptorFromString(
		value,
	)
	if err != nil {
		t.Fatalf("create test descriptor: %v", err)
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
		t.Fatalf("apply test DACL: %v", err)
	}
}

func TestSecureEvidenceFileRejectsHardLink(t *testing.T) {
	store := newTestStore(t)
	file, err := createRecordTemp(store.root, "record.json")
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("close record: %v", err)
	}
	t.Cleanup(func() { removeTestPath(t, path) })
	link := filepath.Join(store.root, "record-link")
	if err := os.Link(path, link); err != nil {
		t.Fatalf("create hard link: %v", err)
	}
	t.Cleanup(func() { removeTestPath(t, link) })
	if err := secureEvidenceFile(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("hard-linked evidence file accepted: %v", err)
	}
}
