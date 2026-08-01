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
			wantErr: "escapes the repository",
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
			wantEscape:  true,
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

func TestModuleReplacementPathErrors(t *testing.T) {
	pathFailure := errors.New("path failure")
	root := t.TempDir()
	target := filepath.Join(root, "inside")
	module, err := modfile.Parse(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/root\n\ngo 1.26.5\n\n"+
			"replace fixture.invalid/a => ./inside\n"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*replacementPathOperations)
		want   string
	}{
		{
			name: "absolute",
			change: func(operations *replacementPathOperations) {
				operations.absolute = func(string) (string, error) {
					return "", pathFailure
				}
			},
			want: "resolve Go module replacement",
		},
		{
			name: "relative",
			change: func(operations *replacementPathOperations) {
				operations.relative = func(string, string) (string, error) {
					return "", pathFailure
				}
			},
			want: "compare Go module replacement",
		},
		{
			name: "physical",
			change: func(operations *replacementPathOperations) {
				operations.physical = func(string) (string, error) {
					return "", pathFailure
				}
			},
			want: "resolve physical Go module replacement",
		},
		{
			name: "physical relative",
			change: func(operations *replacementPathOperations) {
				calls := 0
				operations.relative = func(base, target string) (string, error) {
					calls++
					if calls == 2 {
						return "", pathFailure
					}
					return filepath.Rel(base, target)
				}
			},
			want: "compare physical Go module replacement",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := replacementTestOperations(target)
			test.change(&operations)
			_, err := moduleReplacementEscapesWith(
				filepath.Join(root, "go.mod"),
				module.Replace[0],
				root,
				operations,
			)
			if err == nil || !errors.Is(err, pathFailure) ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q wrapping path failure", err, test.want)
			}
		})
	}
}

func TestVersionedModuleReplacementIsExternal(t *testing.T) {
	t.Parallel()

	module, err := modfile.Parse(
		"go.mod",
		[]byte("module fixture.invalid/root\n\ngo 1.26.5\n\n"+
			"replace mirror.invalid/assurance v1.0.0 => celestia.research/assurance v1.0.0\n"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	escapes, err := moduleReplacementEscapes("go.mod", module.Replace[0], t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !escapes {
		t.Fatal("versioned module replacement was accepted")
	}
}

func replacementTestOperations(target string) replacementPathOperations {
	return replacementPathOperations{
		absolute: func(string) (string, error) { return target, nil },
		relative: filepath.Rel,
		linked:   func(string, string) (bool, error) { return false, nil },
		physical: func(string) (string, error) { return target, nil },
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
