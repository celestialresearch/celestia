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

//go:build windows && amd64

package supervision

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"unicode/utf16"
)

func TestEnvironmentUsesWindowsDirectory(t *testing.T) {
	const poisoned = `C:\untrusted-system-root`
	t.Setenv("SystemRoot", poisoned)
	block, err := environmentBlock(t.TempDir())
	if err != nil {
		t.Fatalf("build environment: %v", err)
	}
	environment := string(utf16.Decode(block))
	if strings.Contains(environment, poisoned) {
		t.Fatal("parent SystemRoot was propagated")
	}
	systemRoot, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatalf("find Windows directory: %v", err)
	}
	if !strings.Contains(environment, "SystemRoot="+systemRoot) {
		t.Fatalf("system root missing from %q", environment)
	}
}

func TestEnvironmentRejectsInvalidTemporaryDirectory(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(folder, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	if _, err := environmentBlock(folder); err == nil {
		t.Fatal("invalid temporary directory accepted")
	}
}

func TestEnvironmentReportsWindowsDirectoryFailure(t *testing.T) {
	t.Parallel()

	expected := errors.New("directory unavailable")
	_, err := environmentBlockWith(
		t.TempDir(),
		func() (string, error) {
			return "", expected
		},
		os.MkdirAll,
		windows.UTF16FromString,
	)
	if !errors.Is(err, expected) {
		t.Fatalf("environmentBlockWith error = %v, want %v", err, expected)
	}
}

func TestEnvironmentReportsEncodingFailure(t *testing.T) {
	t.Parallel()

	expected := errors.New("encoding unavailable")
	_, err := environmentBlockWith(
		t.TempDir(),
		func() (string, error) {
			return `C:\Windows`, nil
		},
		os.MkdirAll,
		func(string) ([]uint16, error) {
			return nil, expected
		},
	)
	if !errors.Is(err, expected) ||
		!strings.Contains(err.Error(), "encode worker environment") {
		t.Fatalf("environmentBlockWith error = %v, want %v", err, expected)
	}
}
