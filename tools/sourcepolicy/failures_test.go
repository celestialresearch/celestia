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
	"context"
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

func TestGoSkipLoadFailures(t *testing.T) {
	target := buildTarget{goos: "linux", goarch: "amd64"}
	loadErr := errors.New("load failed")
	_, err := goSkipFindingsForTargetWith(
		context.Background(),
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
		context.Background(),
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
		context.Background(),
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

func TestGoRaceLoadFlags(t *testing.T) {
	_, err := goSkipFindingsForTargetWith(
		context.Background(),
		buildTarget{
			goos: "linux", goarch: "amd64", cgo: true, race: true,
		},
		[]string{"./..."},
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			if !slices.Equal(config.BuildFlags, []string{"-tags=race"}) {
				t.Errorf("build flags = %v, want race tag", config.BuildFlags)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("race load error = %v", err)
	}
}

func TestGoLoadUsesSourceOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.go")
	source := []byte("package helper\n")
	overlay := map[string][]byte{path: source}
	_, err := goSkipFindingsForTargetWithOverlay(
		context.Background(),
		buildTarget{goos: "linux", goarch: "amd64"},
		[]string{"./..."},
		overlay,
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			if !bytes.Equal(config.Overlay[path], source) {
				t.Errorf("source overlay = %q, want %q", config.Overlay[path], source)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("overlay load error = %v", err)
	}
}

func TestGoBuildUnitsPropagateCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runGoBuildUnitsWith(
		ctx,
		[]goBuildUnit{{
			target:   buildTarget{goos: "linux", goarch: "amd64"},
			patterns: []string{"./..."},
		}},
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			if config.Context != ctx {
				t.Fatal("package loader received a different context")
			}
			return nil, config.Context.Err()
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("load error = %v, want context cancellation", err)
	}
}
