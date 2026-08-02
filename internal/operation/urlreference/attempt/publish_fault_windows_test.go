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

func TestPublishedAttemptDirectoryIsStable(t *testing.T) {
	attempt := &Attempt{path: `C:\evidence\attempt`}
	path, err := attempt.publishDirectory()
	if err != nil || path != attempt.path {
		t.Fatalf("publishDirectory() path = %q, error = %v", path, err)
	}
}

func TestAttemptPreparationRejectsPublishedIdentity(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	if err := createEvidenceDirectory(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("create published fixture: %v", err)
	}
	if _, _, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		createEvidenceDirectory,
	); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("prepareAttemptDirectories() error = %v, want %v", err, ErrDuplicate)
	}
}

func TestAttemptPreparationRejectsInvalidRoot(t *testing.T) {
	accepted, _ := testAccepted(t)
	store := &Store{root: "invalid\x00root"}
	if _, _, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		createEvidenceDirectory,
	); err == nil {
		t.Fatal("invalid attempt root accepted")
	}
}

func TestPublishPendingDirectoryRejectsExistingTarget(t *testing.T) {
	parent := protectedTestDirectory(t)
	source := filepath.Join(parent, "source")
	target := filepath.Join(parent, "target")
	for _, path := range []string{source, target} {
		if err := createEvidenceDirectory(path); err != nil {
			t.Fatalf("create %s: %v", filepath.Base(path), err)
		}
	}
	if _, err := publishPendingDirectory(source, target, parent); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("publishPendingDirectory() error = %v, want %v", err, ErrDuplicate)
	}
}

func TestRemovePendingDirectoryRejectsInvalidState(t *testing.T) {
	t.Run("non-directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pending")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write pending fixture: %v", err)
		}
		if err := removePendingDirectory(path); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("removePendingDirectory() error = %v, want %v", err, ErrCorrupt)
		}
	})

	t.Run("non-empty directory", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "owned")
		if err := createEvidenceDirectory(parent); err != nil {
			t.Fatalf("create protected parent: %v", err)
		}
		path := filepath.Join(parent, "pending")
		if err := createEvidenceDirectory(path); err != nil {
			t.Fatalf("create pending directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "record"), nil, 0o600); err != nil {
			t.Fatalf("write pending record: %v", err)
		}
		if err := removePendingDirectory(path); err == nil {
			t.Fatal("removePendingDirectory() removed a non-empty directory")
		}
	})
}

func TestPublishDirectoryRetainsCleanupFailure(t *testing.T) {
	t.Parallel()

	accepted, _ := testAccepted(t)
	failure := errors.New("injected pending cleanup failure")
	attempt := &Attempt{
		store:       &Store{root: `C:\evidence`},
		path:        `C:\evidence\pending\attempt`,
		pendingPath: `C:\evidence\pending`,
		admitted:    Admitted{AttemptID: accepted.Request.AttemptID},
	}
	path, err := attempt.publishDirectoryWith(pendingPublicationOperations{
		publish: func(string, string, string) (string, error) {
			return `C:\evidence\attempts\attempt`, nil
		},
		remove: func(string) error { return failure },
	})
	if path != "" || !errors.Is(err, failure) ||
		attempt.pendingPath != "" {
		t.Fatalf(
			"path = %q, error = %v, pending = %q",
			path,
			err,
			attempt.pendingPath,
		)
	}
}

func TestRemovePendingReportsSecurityFailure(t *testing.T) {
	t.Parallel()

	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	failure := errors.New("injected pending security failure")
	err = removePendingDirectoryWith(
		"unused",
		pendingRemovalOperations{
			lstat:  func(string) (os.FileInfo, error) { return info, nil },
			linked: func(string, os.FileInfo) bool { return false },
			secure: func(string) error { return failure },
			remove: func(string) error {
				t.Fatal("remove called after security failure")
				return nil
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("removePendingDirectoryWith() error = %v", err)
	}
}

func TestPublishRejectsFinalDirectoryCollision(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := createEvidenceDirectory(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("create final collision: %v", err)
	}
	err = attempt.Publish(testObservationFor(t, accepted))
	if !errors.Is(err, ErrPublication) || !errors.Is(err, ErrDuplicate) {
		t.Fatalf("final collision accepted: %v", err)
	}
}

func TestRemovePendingRejectsInvalidPath(t *testing.T) {
	if err := removePendingDirectory("invalid\x00path"); err == nil {
		t.Fatal("invalid pending path accepted")
	}
}

func TestPendingPublicationRefusesExistingTarget(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create directory: %v", err)
		}
	}
	if _, err := publishPendingDirectory(source, target, root); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("existing target replaced: %v", err)
	}
	if exists, err := pathExists(filepath.Join(root, "missing")); err != nil || exists {
		t.Fatalf("missing path: exists=%t error=%v", exists, err)
	}
	if exists, err := pathExists(source); err != nil || !exists {
		t.Fatalf("existing path: exists=%t error=%v", exists, err)
	}
	if _, err := pathExists("invalid\x00path"); err == nil {
		t.Fatal("invalid path accepted")
	}
}

func TestPendingPublicationRequiresSource(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	if err := os.RemoveAll(source); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	if err := os.RemoveAll(target); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if _, err := publishPendingDirectory(source, target, root); err == nil {
		t.Fatal("missing source published")
	}
}

func TestPendingPublicationRejectsInvalidTarget(t *testing.T) {
	if _, err := publishPendingDirectory(
		t.TempDir(),
		"invalid\x00target",
		t.TempDir(),
	); err == nil {
		t.Fatal("invalid publication target accepted")
	}
}

func TestStoreReportsWriteFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if err := os.Rename(attempt.path, attempt.path+".moved"); err != nil {
		t.Fatalf("move attempt: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err == nil {
		t.Fatal("missing attempt directory accepted publication")
	}
}
