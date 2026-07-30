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
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

func moduleFixture(source string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) {
		return []byte(source), nil
	}
}

func TestRejectExternalModuleReplacements(t *testing.T) {
	readFailure := errors.New("read failure")
	tests := []struct {
		name    string
		paths   []string
		read    func(string) ([]byte, error)
		wantErr string
	}{
		{
			name:  "empty inventory",
			paths: nil,
			read:  os.ReadFile,
		},
		{
			name:  "unrelated file",
			paths: []string{"source.go"},
			read:  os.ReadFile,
		},
		{
			name:  "read failure",
			paths: []string{"go.mod"},
			read: func(string) ([]byte, error) {
				return nil, readFailure
			},
			wantErr: readFailure.Error(),
		},
		{
			name:    "malformed module",
			paths:   []string{"go.mod"},
			read:    moduleFixture("not a module"),
			wantErr: "parse Go module",
		},
		{
			name:  "no replacements",
			paths: []string{"go.mod"},
			read:  moduleFixture("module fixture.invalid/root\n\ngo 1.26.5\n"),
		},
		{
			name:  "version replacement",
			paths: []string{"go.mod"},
			read: moduleFixture("module fixture.invalid/root\n\ngo 1.26.5\n\n" +
				"replace fixture.invalid/a => fixture.invalid/b v1.0.0\n"),
		},
		{
			name:  "missing local replacement",
			paths: []string{"go.mod"},
			read: moduleFixture("module fixture.invalid/root\n\ngo 1.26.5\n\n" +
				"replace fixture.invalid/a => ./missing\n"),
			wantErr: "inspect Go module replacement path",
		},
		{
			name:  "escaping replacement",
			paths: []string{"go.mod"},
			read: moduleFixture("module fixture.invalid/root\n\ngo 1.26.5\n\n" +
				"replace fixture.invalid/a => ../outside\n"),
			wantErr: "escapes the repository",
		},
	}

	root := t.TempDir()
	t.Chdir(root)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := rejectExternalModuleReplacements(test.paths, test.read)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("reject replacements: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestModuleReplacementContainment(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "inside")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	modulePath := filepath.Join(root, "go.mod")

	tests := []struct {
		name        string
		replacement string
		wantEscape  bool
		wantErr     string
	}{
		{
			name:        "module version",
			replacement: "fixture.invalid/b v1.0.0",
		},
		{
			name:        "relative inside",
			replacement: "./inside",
		},
		{
			name:        "absolute inside",
			replacement: filepath.ToSlash(inside),
		},
		{
			name:        "relative escape",
			replacement: "../outside",
			wantEscape:  true,
		},
		{
			name:        "missing inside",
			replacement: "./missing",
			wantErr:     "inspect Go module replacement path",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module, err := modfile.Parse(
				modulePath,
				[]byte("module fixture.invalid/root\n\ngo 1.26.5\n\n"+
					"replace fixture.invalid/a => "+test.replacement+"\n"),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			escapes, err := moduleReplacementEscapes(
				modulePath,
				module.Replace[0],
				root,
			)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if escapes != test.wantEscape {
				t.Fatalf("escapes = %v, want %v", escapes, test.wantEscape)
			}
		})
	}
}

func TestPathEscapesRoot(t *testing.T) {
	tests := map[string]bool{
		".":      false,
		"inside": false,
		"..":     true,
		".." + string(os.PathSeparator) + "outside": true,
		"..outside": false,
	}
	for path, want := range tests {
		if got := pathEscapesRoot(path); got != want {
			t.Errorf("pathEscapesRoot(%q) = %v, want %v", path, got, want)
		}
	}
}
