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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestReadSourceFailures(t *testing.T) {
	rootPath := t.TempDir()
	filePath := filepath.Join(rootPath, "source.go")
	if err := os.WriteFile(filePath, []byte("package source"), 0o600); err != nil {
		t.Fatal(err)
	}
	openRoot := func(string) (*os.Root, error) {
		return os.OpenRoot(rootPath)
	}
	openFile := func(root *os.Root, name string) (*os.File, error) {
		return root.Open(name)
	}
	realStat := func(file *os.File) (os.FileInfo, error) {
		return file.Stat()
	}
	failure := errors.New("injected failure")
	tests := []struct {
		name   string
		reader sourceReader
	}{
		{
			name: "open root",
			reader: sourceReader{
				openRoot: func(string) (*os.Root, error) { return nil, failure },
			},
		},
		{
			name: "open file",
			reader: sourceReader{
				openRoot: openRoot,
				openFile: func(*os.Root, string) (*os.File, error) {
					return nil, failure
				},
			},
		},
		{
			name: "stat",
			reader: sourceReader{
				openRoot: openRoot,
				openFile: openFile,
				stat: func(*os.File) (os.FileInfo, error) {
					return nil, failure
				},
			},
		},
		{
			name: "read",
			reader: sourceReader{
				openRoot: openRoot,
				openFile: openFile,
				stat:     realStat,
				read: func(io.Reader) ([]byte, error) {
					return nil, failure
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readSourceWith("source.go", test.reader)
			if !errors.Is(err, failure) {
				t.Fatalf("readSourceWith error = %v, want %v", err, failure)
			}
		})
	}

	source, err := readSourceWith("source.go", sourceReader{
		openRoot: openRoot,
		openFile: openFile,
		stat:     realStat,
		read: func(io.Reader) ([]byte, error) {
			return bytes.Repeat([]byte{'x'}, maxSourceBytes+1), nil
		},
	})
	if err == nil || source != nil ||
		!strings.Contains(err.Error(), "source file exceeds") {
		t.Fatalf("grown source = %d bytes, %v", len(source), err)
	}
}

func TestGoSkipLoadFailures(t *testing.T) {
	target := buildTarget{goos: "linux", goarch: "amd64"}
	loadErr := errors.New("load failed")
	_, err := goSkipFindingsForTargetWith(
		target,
		[]string{"./..."},
		func(*packages.Config, ...string) ([]*packages.Package, error) {
			return nil, loadErr
		},
	)
	if !errors.Is(err, loadErr) {
		t.Fatalf("load error = %v, want %v", err, loadErr)
	}

	_, err = goSkipFindingsForTargetWith(
		target,
		[]string{"./..."},
		func(*packages.Config, ...string) ([]*packages.Package, error) {
			return []*packages.Package{{
				Errors: []packages.Error{{Msg: "package failed"}},
			}}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "package failed") {
		t.Fatalf("package error = %v", err)
	}

	_, err = goSkipFindingsForTargetWith(
		buildTarget{goos: "linux", goarch: "amd64", cgo: true},
		[]string{"./..."},
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			for _, value := range []string{
				"GOOS=linux",
				"GOARCH=amd64",
				"CGO_ENABLED=1",
			} {
				if !slices.Contains(config.Env, value) {
					t.Errorf("environment omits %q", value)
				}
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("CGO load error = %v", err)
	}
}
