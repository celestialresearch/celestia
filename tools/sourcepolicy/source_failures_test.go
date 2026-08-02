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
	"strings"
	"testing"
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
	statPath := func(root *os.Root, name string) (os.FileInfo, error) {
		return root.Stat(name)
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
				statPath: statPath,
				openFile: func(*os.Root, string) (*os.File, error) {
					return nil, failure
				},
			},
		},
		{
			name: "stat path",
			reader: sourceReader{
				openRoot: openRoot,
				statPath: func(*os.Root, string) (os.FileInfo, error) {
					return nil, failure
				},
			},
		},
		{
			name: "stat",
			reader: sourceReader{
				openRoot: openRoot,
				statPath: statPath,
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
				statPath: statPath,
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
}

func TestReadSourcePostOpenType(t *testing.T) {
	rootPath := t.TempDir()
	filePath := filepath.Join(rootPath, "source.go")
	if err := os.WriteFile(filePath, []byte("package source"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	read := false
	_, err = readSourceWith("source.go", sourceReader{
		openRoot: func(string) (*os.Root, error) {
			return os.OpenRoot(rootPath)
		},
		statPath: (*os.Root).Stat,
		openFile: func(root *os.Root, name string) (*os.File, error) {
			return root.Open(name)
		},
		stat: func(*os.File) (os.FileInfo, error) {
			return directory, nil
		},
		read: func(io.Reader) ([]byte, error) {
			read = true
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("post-open type error = %v", err)
	}
	if read {
		t.Fatal("post-open non-regular source was read")
	}
}

func TestReadSourceGrowth(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(rootPath, "source.go"),
		[]byte("package source"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source, err := readSourceWith("source.go", sourceReader{
		openRoot: func(string) (*os.Root, error) {
			return os.OpenRoot(rootPath)
		},
		statPath: (*os.Root).Stat,
		openFile: func(root *os.Root, name string) (*os.File, error) {
			return root.Open(name)
		},
		stat: (*os.File).Stat,
		read: func(io.Reader) ([]byte, error) {
			return bytes.Repeat([]byte{'x'}, maxSourceBytes+1), nil
		},
	})
	if err == nil || source != nil ||
		!strings.Contains(err.Error(), "source file exceeds") {
		t.Fatalf("grown source = %d bytes, %v", len(source), err)
	}
}
