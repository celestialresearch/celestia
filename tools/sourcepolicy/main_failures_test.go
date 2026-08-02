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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunFailureReporting(t *testing.T) {
	inventoryFailure := func() ([]string, error) {
		return nil, errors.New("inventory failed")
	}
	validInventory := func() ([]string, error) {
		return []string{"broken_test.go"}, nil
	}
	readBrokenGo := func(string) ([]byte, error) {
		return []byte("package broken\nfunc TestBroken("), nil
	}
	readEmpty := func(string) ([]byte, error) { return nil, nil }
	tests := []struct {
		name      string
		args      []string
		inventory func() ([]string, error)
		read      func(string) ([]byte, error)
	}{
		{"usage write", nil, validInventory, readEmpty},
		{"inventory write", []string{modeTestSkips}, inventoryFailure, readEmpty},
		{"policy write", []string{modeTestSkips}, validInventory, readBrokenGo},
		{"finding write", []string{modeSuppressions}, validInventory, func(string) ([]byte, error) {
			return []byte("//no" + "lint"), nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if code := run(test.args, failingWriter{}, test.inventory, test.read); code != 1 {
				t.Fatalf("run code = %d, want 1", code)
			}
		})
	}

	var stderr bytes.Buffer
	if code := run(
		[]string{modeTestSkips},
		&stderr,
		validInventory,
		readBrokenGo,
	); code != 1 || !strings.Contains(stderr.String(), "parse Go test") {
		t.Fatalf("policy failure = %d, %q", code, stderr.String())
	}
}

func TestQuotedDiagnosticPreservesCause(t *testing.T) {
	t.Parallel()
	cause := errors.New("hostile\n\t\x1b\u202e")
	err := fmt.Errorf("parse source: %w", quotedDiagnostic(cause))
	assertSafeDiagnostic(t, err.Error())
	if !errors.Is(err, cause) {
		t.Fatal("quoted diagnostic lost its cause")
	}
}

func TestGoParserDiagnosticsQuoteLocations(t *testing.T) {
	t.Parallel()
	source := []byte("//line hostile\x1b[31m.go:1\npackage fixture\nfunc")
	importSource := []byte("//line hostile\x1b[31m.go:1\npackage fixture\nimport")
	temporary := filepath.Join(t.TempDir(), "fixture_test.go")
	if err := os.WriteFile(temporary, source, 0o600); err != nil {
		t.Fatalf("write parser fixture: %v", err)
	}
	absolute, err := filepath.Abs("fixture.go")
	if err != nil {
		t.Fatalf("resolve overlay fixture: %v", err)
	}
	for name, parse := range map[string]func() error{
		"architecture documentation": func() error {
			return observePackageDocumentation(
				"internal/fixture/doc.go", []string{"internal/fixture"}, map[string]bool{},
				func(string) ([]byte, error) { return source, nil },
			)
		},
		"architecture imports": func() error {
			_, parseErr := architectureImportFindings(
				[]string{"internal/fixture/file.go"}, func(string) ([]byte, error) { return importSource, nil },
			)
			return parseErr
		},
		"build tags": func() error {
			return rejectUnsupportedBuildTags("fixture.go", source)
		},
		"cgo overlay": func() error {
			_, parseErr := goSourceImportsC("fixture.go", map[string][]byte{absolute: importSource})
			return parseErr
		},
		"test selector": func() error {
			_, parseErr := hasGoPolicySelector("fixture_test.go", source)
			return parseErr
		},
		"test inventory": func() error {
			_, parseErr := testsInFile(temporary)
			return parseErr
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			parseErr := parse()
			if parseErr == nil {
				t.Fatal("hostile parser fixture was accepted")
			}
			assertSafeDiagnostic(t, parseErr.Error())
		})
	}
}

func TestFindingDiagnosticsQuoteParserErrors(t *testing.T) {
	t.Parallel()
	source := []byte("//line hostile\x1b[31m.go:1\npackage fixture\nfunc")
	findings := goSkipFindings("fixture_test.go", source)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one parser finding", findings)
	}
	assertSafeDiagnostic(t, findings[0])
}

func TestConstraintDiagnosticQuotesInput(t *testing.T) {
	t.Parallel()
	source := []byte("//go:build windows || hostile\x1b[31m\n\npackage fixture\n")
	err := rejectUnsupportedBuildTags("fixture.go", source)
	if err == nil {
		t.Fatal("hostile build constraint was accepted")
	}
	assertSafeDiagnostic(t, err.Error())
}

func TestModuleDiagnosticQuotesInput(t *testing.T) {
	t.Parallel()
	source := []byte("module example.test/fixture\nhostile\x1b[31m\n")
	err := rejectModuleReplacements(
		[]string{"go.mod"}, func(string) ([]byte, error) { return source, nil },
	)
	if err == nil {
		t.Fatal("hostile module fixture was accepted")
	}
	assertSafeDiagnostic(t, err.Error())
}

func assertSafeDiagnostic(t *testing.T, diagnostic string) {
	t.Helper()
	for _, character := range diagnostic {
		if character < 0x20 || character == 0x7f || character > 0x7e {
			t.Fatalf("diagnostic contains an unsafe character: %q", diagnostic)
		}
	}
}
