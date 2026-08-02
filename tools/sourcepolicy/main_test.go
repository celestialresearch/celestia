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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	rustSkipPath := filepath.Join(root, "skipped.rs")
	rustPath := filepath.Join(root, "suppressed.rs")
	missingRustPath := filepath.Join(root, "missing.rs")
	if err := os.WriteFile(
		rustSkipPath, []byte("#[ignore]\nfn skipped() {}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		rustPath, []byte("#![allow(clippy::all)]"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		args      []string
		inventory func() ([]string, error)
		code      int
		output    string
	}{
		{
			"usage",
			nil,
			func() ([]string, error) { return nil, nil },
			2,
			"usage:",
		},
		{
			"inventory failure",
			[]string{modeTestSkips},
			func() ([]string, error) { return nil, errors.New("inventory failed") },
			1,
			"inventory failed",
		},
		{
			"Rust skip",
			[]string{modeTestSkips},
			func() ([]string, error) { return []string{rustSkipPath}, nil },
			1,
			"Rust tests must not ignore",
		},
		{
			"Rust suppression",
			[]string{modeSuppressions},
			func() ([]string, error) { return []string{rustPath}, nil },
			1,
			"invalid Clippy suppression",
		},
		{
			"missing Rust source",
			[]string{modeTestSkips},
			func() ([]string, error) { return []string{missingRustPath}, nil },
			1,
			"missing.rs",
		},
		{
			"missing Cargo workspace",
			[]string{modeSuppressions},
			func() ([]string, error) { return []string{"README.md"}, nil },
			1,
			"missing governed Cargo workspace",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			code := run(test.args, &stderr, test.inventory, os.ReadFile)
			if code != test.code {
				t.Fatalf("code = %d, want %d", code, test.code)
			}
			if !strings.Contains(stderr.String(), test.output) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.output)
			}
		})
	}
}

func TestRunRejectsCargoSuppression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Cargo.toml")
	if err := os.WriteFile(
		path,
		[]byte("[lints.clippy]\nall = \"allow\"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := run(
		[]string{modeSuppressions},
		&stderr,
		func() ([]string, error) { return []string{path}, nil },
		os.ReadFile,
	)
	if code != 1 ||
		!strings.Contains(stderr.String(), "Cargo lint allowances are prohibited") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunRejectsGolangciExclusions(t *testing.T) {
	t.Parallel()
	for _, owner := range []string{"linters", "formatters"} {
		t.Run(owner, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), ".golangci.yml")
			source := []byte(
				"version: \"2\"\n" + owner +
					":\n  exclusions:\n    paths:\n      - internal\n",
			)
			if err := os.WriteFile(path, source, 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			code := run(
				[]string{modeSuppressions},
				&stderr,
				func() ([]string, error) { return []string{path}, nil },
				os.ReadFile,
			)
			if code != 1 ||
				!strings.Contains(stderr.String(), "exclusions are prohibited") {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
		})
	}
}

func TestRunRejectsAlternateGolangciConfigs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		".golangci.yaml",
		".golangci.toml",
		".golangci.json",
		".GOLANGCI.YML",
		".GoLaNgCi.YaMl",
		".GolangCI.TOML",
		".golangCI.JSON",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			code := run(
				[]string{modeSuppressions},
				&stderr,
				func() ([]string, error) { return []string{path}, nil },
				os.ReadFile,
			)
			if code != 1 ||
				!strings.Contains(
					stderr.String(),
					"alternate golangci-lint configurations are prohibited",
				) {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
		})
	}
}
