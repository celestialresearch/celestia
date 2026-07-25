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

//go:build !windows

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNewRejectsInsecureUnixRootMode(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Chmod(root, 0o777); err != nil {
		t.Fatalf("loosen root: %v", err)
	}
	if _, err := New(root); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("insecure root accepted: %v", err)
	}
}

func TestNewCreatesSecureUnixTree(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	for _, path := range []string{store.root, store.attemptsPath(), store.pendingRoot()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat secured path: %v", err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode=%#o", path, info.Mode().Perm())
		}
	}
}

func TestSecureEvidenceTreeRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := secureEvidenceTree(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-directory accepted: %v", err)
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

func TestSyncDirectoryRejectsMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if err := syncDirectory(path); err == nil {
		t.Fatal("missing directory accepted")
	}
}
