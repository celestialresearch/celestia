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

//go:build linux && amd64

package attemptstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxEvidenceFilesystemTypes(t *testing.T) {
	t.Parallel()

	if !validEvidenceFilesystemType("ext4") || !validEvidenceFilesystemType("xfs") ||
		validEvidenceFilesystemType("ext3") || validEvidenceFilesystemType("") {
		t.Fatal("filesystem allowlist is incorrect")
	}
}

func TestLinuxPublicationDoesNotReplace(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	writeLinuxFixture(t, source, "source")
	writeLinuxFixture(t, target, "target")
	if err := publishFile(source, target, root); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("publishFile() error = %v", err)
	}
	assertLinuxFixture(t, source, "source")
	assertLinuxFixture(t, target, "target")

	sourceDirectory := filepath.Join(root, "source-directory")
	targetDirectory := filepath.Join(root, "target-directory")
	if err := os.Mkdir(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectory(sourceDirectory, targetDirectory, root); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("publishDirectory() error = %v", err)
	}
}

func TestLinuxPublicationMovesExactEntry(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	writeLinuxFixture(t, source, "record")
	if err := publishFile(source, target, root); err != nil {
		t.Fatalf("publishFile() error = %v", err)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source error = %v", err)
	}
	assertLinuxFixture(t, target, "record")
}

func TestLinuxAttemptLockExcludesSecondOwner(t *testing.T) {
	t.Parallel()

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close lock root: %v", err)
		}
	})
	first, err := root.OpenFile("lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("close first lock: %v", err)
		}
	})
	second, err := root.OpenFile("lock", os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second lock: %v", err)
		}
	})
	if err := lockAttemptFile(first); err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if err := lockAttemptFile(second); !errors.Is(err, errLockHeld) {
		t.Fatalf("second lock: %v", err)
	}
	if err := unlockAttemptFile(first); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

func writeLinuxFixture(t *testing.T, path, value string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	file, createErr := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if createErr != nil {
		t.Fatal(errors.Join(createErr, root.Close()))
	}
	_, writeErr := file.WriteString(value)
	if err := errors.Join(writeErr, file.Close(), root.Close()); err != nil {
		t.Fatal(err)
	}
}

func assertLinuxFixture(t *testing.T, path, expected string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	file, openErr := root.Open(filepath.Base(path))
	if openErr != nil {
		t.Fatal(errors.Join(openErr, root.Close()))
	}
	actual, readErr := io.ReadAll(file)
	err = errors.Join(readErr, file.Close(), root.Close())
	if err != nil || string(actual) != expected {
		t.Fatalf("read %s: value=%q error=%v", path, actual, err)
	}
}
