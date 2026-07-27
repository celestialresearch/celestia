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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestNewRejectsInsecureUnixParent(t *testing.T) {
	parent := t.TempDir()
	if err := syscall.Chmod(parent, 0o777); err != nil {
		t.Fatalf("loosen parent: %v", err)
	}
	if _, err := New(filepath.Join(parent, "evidence")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("insecure parent accepted: %v", err)
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

func TestSecureEvidenceFileRejectsLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := secureEvidenceFile(path); err != nil {
		t.Fatalf("secure record rejected: %v", err)
	}
	if err := syscall.Chmod(path, 0o644); err != nil {
		t.Fatalf("loosen record: %v", err)
	}
	if err := secureEvidenceFile(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loosely readable record accepted: %v", err)
	}
}

func TestStageRejectsLinkedAttemptPath(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	if err := os.Symlink(
		t.TempDir(),
		store.finalPath(accepted.Request.AttemptID),
	); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked attempt path accepted: %v", err)
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

func TestRecoverRepairsLinkedRecord(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	path := attempt.path
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	temporary := filepath.Join(path, "."+admittedFile+"."+strings.Repeat("a", 32))
	if err := os.Link(filepath.Join(path, admittedFile), temporary); err != nil {
		t.Fatalf("link interrupted record: %v", err)
	}

	if err := store.Recover(accepted.Request.AttemptID, "writer interrupted"); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary record remains: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if records.Recovery == nil {
		t.Fatal("recovery record is missing")
	}
}

func TestRecoverRemovesOrphanRecordTemp(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	path := attempt.path
	if err := attempt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	temporary := filepath.Join(path, "."+observationFile+"."+strings.Repeat("b", 32))
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write interrupted record: %v", err)
	}

	if err := store.Recover(accepted.Request.AttemptID, "writer interrupted"); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary record remains: %v", err)
	}
}

func TestRepairValidatesBeforeRemoval(t *testing.T) {
	t.Parallel()

	path := t.TempDir()
	valid := filepath.Join(path, "."+admittedFile+"."+strings.Repeat("c", 32))
	invalid := filepath.Join(path, "."+receiptFile+"."+strings.Repeat("d", 32))
	if err := os.WriteFile(valid, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write valid temporary record: %v", err)
	}
	if err := os.Mkdir(invalid, 0o700); err != nil {
		t.Fatalf("write invalid temporary record: %v", err)
	}

	if err := repairInterruptedRecords(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("repair error = %v, want ErrCorrupt", err)
	}
	if _, err := os.Lstat(valid); err != nil {
		t.Fatalf("valid temporary record was removed: %v", err)
	}
}

func TestRepairRejectsUnpairedLinkedTemporary(t *testing.T) {
	t.Parallel()

	path := t.TempDir()
	source := filepath.Join(path, "unrelated")
	temporary := filepath.Join(path, "."+receiptFile+"."+strings.Repeat("e", 32))
	if err := os.WriteFile(source, []byte("unrelated"), 0o600); err != nil {
		t.Fatalf("write unrelated record: %v", err)
	}
	if err := os.Link(source, temporary); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	if err := repairInterruptedRecords(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("repair error = %v, want ErrCorrupt", err)
	}
	if _, err := os.Lstat(temporary); err != nil {
		t.Fatalf("corrupt temporary was removed: %v", err)
	}
}
