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

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGoSkipCandidateFailures(t *testing.T) {
	t.Parallel()
	_, _, err := goCandidateDirectories(
		[]string{"broken_test.go"},
		func(string) ([]byte, error) {
			return []byte("package fixture\nfunc TestBroken("), nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "parse Go test") {
		t.Fatalf("parse error = %v", err)
	}

	readErr := errors.New("read failure")
	_, _, err = goCandidateDirectories(
		[]string{"unreadable_test.go"},
		func(string) ([]byte, error) { return nil, readErr },
	)
	if !errors.Is(err, readErr) {
		t.Fatalf("read error = %v, want %v", err, readErr)
	}
}

func TestGoBuildSelectionRejectsInvalidConstraint(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "invalid_test.go")
	if err := os.WriteFile(
		path,
		[]byte("//go:build linux &&\n\npackage fixture\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err := goBuildSelection(
		[]string{path},
		map[string]bool{root: true},
		buildTarget{goos: "linux", goarch: "amd64"},
		map[string][]byte{
			path: []byte("//go:build linux &&\n\npackage fixture\n"),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "match Go build constraints") {
		t.Fatalf("constraint error = %v", err)
	}
}

func TestGoBuildSelectionUsesOverlay(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "selected_test.go")
	if err := os.WriteFile(
		path,
		[]byte("//go:build windows\n\npackage fixture\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	patterns, err := goBuildSelection(
		[]string{path},
		map[string]bool{root: true},
		buildTarget{goos: "linux", goarch: "amd64"},
		map[string][]byte{
			path: []byte("//go:build linux\n\npackage fixture\n"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(patterns, []string{"file=" + filepath.ToSlash(path)}) {
		t.Fatalf("patterns = %v, want overlay-selected file", patterns)
	}
}
