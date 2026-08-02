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

func TestPublishFileRejectsInvalidPaths(t *testing.T) {
	if err := publishFile("invalid\x00source", "target", t.TempDir()); err == nil {
		t.Fatal("invalid source path accepted")
	}
	if err := publishFile("source", "invalid\x00target", t.TempDir()); err == nil {
		t.Fatal("invalid target path accepted")
	}
}

func removeTestPath(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove test path: %v", err)
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
