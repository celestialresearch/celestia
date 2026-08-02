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
	"runtime"
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

func TestGoPolicyRejectsTestsOutsideTargetMatrix(t *testing.T) {
	for _, name := range []string{"hidden_android_test.go", "hidden_386_test.go"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, name)
			source := []byte("package fixture\n\nimport \"testing\"\n\n" +
				"func TestHidden(t *testing.T) { t.Fatal(\"hidden\") }\n")
			if err := os.WriteFile(path, source, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(root)
			_, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Base(path)},
				os.ReadFile,
				[]buildTarget{{goos: "linux", goarch: "amd64"}},
			)
			if err == nil || !strings.Contains(err.Error(), "governed target matrix") {
				t.Fatalf("selection error = %v", err)
			}
		})
	}
}

func TestGoIgnoredTestPathDistinguishesExternalFixtures(t *testing.T) {
	t.Parallel()
	external := filepath.Join(t.TempDir(), "hidden_android_test.go")
	if goIgnoredTestPath(external) {
		t.Fatalf("external fixture classified as repository exclusion: %s", external)
	}
	for _, path := range []string{
		"_hidden_test.go",
		".hidden_test.go",
		filepath.Join("_hidden", "failure_test.go"),
		filepath.Join(".hidden", "failure_test.go"),
		filepath.Join("testdata", "failure_test.go"),
		filepath.Join("vendor", "failure_test.go"),
	} {
		if !goIgnoredTestPath(path) {
			t.Errorf("repository exclusion accepted: %s", path)
		}
	}
}

func TestGoPolicyRejectsTestsOutsidePackageInventory(t *testing.T) {
	for _, directory := range []string{"_hidden", ".hidden", "testdata", "vendor"} {
		t.Run(directory, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, directory, "failure_test.go")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				path,
				[]byte("package fixture\n\nimport \"testing\"\n\n"+
					"func TestHidden(t *testing.T) { t.Fatal(\"hidden\") }\n"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			t.Chdir(root)
			_, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Join(directory, "failure_test.go")},
				os.ReadFile,
				[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
			)
			if err == nil || !strings.Contains(err.Error(), "governed package inventory") {
				t.Fatalf("inventory error = %v", err)
			}
		})
	}
}

func TestGoPolicyClassifiesIgnoredTestsBeforeContent(t *testing.T) {
	tests := []struct {
		name    string
		sources map[string]string
	}{
		{
			"malformed",
			map[string]string{"_hidden/failure_test.go": "package fixture\nfunc Test("},
		},
		{
			"build tag",
			map[string]string{
				"_hidden/failure_test.go": "//go:build privatecheck\n\npackage fixture\n",
			},
		},
		{
			"native source",
			map[string]string{
				"_hidden/failure_amd64.s": "TEXT ·entry(SB),$0-0\n\tRET\n",
				"_hidden/failure_test.go": "package fixture\n",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeGoPolicyFixture(t, root, test.sources)
			t.Chdir(root)
			paths := make([]string, 0, len(test.sources))
			for path := range test.sources {
				paths = append(paths, filepath.FromSlash(path))
			}
			_, err := goPackageSkipFindingsWithTargets(
				paths,
				os.ReadFile,
				[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
			)
			if err == nil || !strings.Contains(err.Error(), "governed package inventory") {
				t.Fatalf("classification error = %v", err)
			}
		})
	}
}
