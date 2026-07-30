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
)

func TestRun(t *testing.T) {
	root := t.TempDir()
	goPath := filepath.Join(root, "skipped_test.go")
	rustPath := filepath.Join(root, "suppressed.rs")
	missingRustPath := filepath.Join(root, "missing.rs")
	if err := os.WriteFile(goPath, []byte(
		"package fixture\nimport \"testing\"\n"+
			"func TestFixture(t *testing.T) { t.SkipNow() }\n",
	), 0o600); err != nil {
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
			"Go skip",
			[]string{modeTestSkips},
			func() ([]string, error) { return []string{goPath}, nil },
			1,
			"Go tests must not skip",
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
			"irrelevant file",
			[]string{modeSuppressions},
			func() ([]string, error) { return []string{"README.md"}, nil },
			0,
			"",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

func TestReadSourceBoundsRepository(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(parent, "outside.rs"), []byte("outside"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "source.rs"), []byte("inside"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, maxSourceBytes+1)
	if err := os.WriteFile(
		filepath.Join(root, "oversized.rs"), oversized, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	source, err := readSource("source.rs")
	if err != nil || string(source) != "inside" {
		t.Fatalf("readSource(source.rs) = %q, %v", source, err)
	}
	for _, path := range []string{
		"../outside.rs",
		".",
		"oversized.rs",
	} {
		if _, err := readSource(path); err == nil {
			t.Fatalf("readSource(%q) succeeded", path)
		}
	}
}

func TestSourceFiles(t *testing.T) {
	t.Parallel()
	files, err := readInventory(strings.NewReader("first.go\x00second.rs\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, []string{"first.go", "second.rs"}) {
		t.Fatalf("files = %v", files)
	}
	tests := []struct {
		name   string
		source io.Reader
	}{
		{"unterminated", strings.NewReader("first.go")},
		{"empty", strings.NewReader("\x00")},
		{
			"long path",
			strings.NewReader("aaaaaaaaa\x00"),
		},
		{
			"too many paths",
			strings.NewReader("a\x00b\x00"),
		},
		{
			"too many bytes",
			strings.NewReader("aa\x00bb\x00"),
		},
		{"read failure", failingReader{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			maxBytes, maxPaths, maxPathBytes := 64, 8, 8
			switch test.name {
			case "too many paths":
				maxPaths = 1
			case "too many bytes":
				maxBytes = 5
			}
			if _, err := readInventoryWithLimits(
				test.source, maxBytes, maxPaths, maxPathBytes,
			); err == nil {
				t.Fatal("readInventory accepted invalid input")
			}
		})
	}
}

func TestSourceFilesCommand(t *testing.T) {
	t.Parallel()
	files, err := inventorySourceFiles("git", func(
		context.Context,
		string,
		...string,
	) inventoryCommand {
		return &fakeInventoryCommand{
			output: strings.NewReader("main.go\x00"),
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(files, "main.go") {
		t.Fatalf("source inventory does not contain sourcepolicy: %v", files)
	}
	tests := []struct {
		name    string
		command *fakeInventoryCommand
	}{
		{"pipe failure", &fakeInventoryCommand{pipeErr: errors.New("pipe failed")}},
		{"start failure", &fakeInventoryCommand{startErr: errors.New("start failed")}},
		{
			"read failure",
			&fakeInventoryCommand{output: failingReader{}},
		},
		{
			"wait failure",
			&fakeInventoryCommand{
				output:  strings.NewReader("main.go\x00"),
				waitErr: errors.New("wait failed"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := inventorySourceFiles("git", func(
				context.Context,
				string,
				...string,
			) inventoryCommand {
				return test.command
			})
			if err == nil {
				t.Fatal("inventorySourceFiles accepted a command failure")
			}
		})
	}
}

type fakeInventoryCommand struct {
	output   io.Reader
	pipeErr  error
	startErr error
	waitErr  error
}

func (command *fakeInventoryCommand) Start() error {
	return command.startErr
}

func (command *fakeInventoryCommand) StdoutPipe() (io.ReadCloser, error) {
	if command.pipeErr != nil {
		return nil, command.pipeErr
	}
	return io.NopCloser(command.output), nil
}

func (command *fakeInventoryCommand) Wait() error {
	return command.waitErr
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestGoSkipMethods(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		call     string
		findings int
	}{
		{"receiver", `t.Skip("unverified")`, 1},
		{"renamed receiver", `testCase.SkipNow()`, 1},
		{"method expression", `(*testing.T).Skip(t, "unverified")`, 1},
		{
			"custom method",
			`cursor{}.Skip(1)`,
			0,
		},
		{"ordinary test", `t.Log("verified")`, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "fixture_test.go")
			parameter := "t"
			if test.name == "renamed receiver" {
				parameter = "testCase"
			}
			source := "package fixture\n\nimport \"testing\"\n\n" +
				"type cursor struct{}\n" +
				"func (cursor) Skip(int) {}\n\n" +
				"func TestFixture(" + parameter + " *testing.T) {\n" +
				test.call + "\n}\n"
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			findings := goSkipFindings(path, []byte(source))
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestRustPolicyAttributes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		mode     string
		findings int
	}{
		{"ignore", "#[ignore]\nfn test() {}", modeTestSkips, 1},
		{"conditional ignore", "#[cfg_attr(all(), ignore)]\nfn test() {}", modeTestSkips, 1},
		{"inner allow", "#![allow(clippy::all)]", modeSuppressions, 1},
		{"inner expect", "#![expect(clippy::all)]", modeSuppressions, 1},
		{
			"reasoned allow",
			`#[allow(clippy::needless_pass_by_value, reason = "FFI owns the value")]`,
			modeSuppressions,
			0,
		},
		{"comment", "// #[ignore]\nfn test() {}", modeTestSkips, 0},
		{"string", `const VALUE: &str = "#[ignore]";`, modeTestSkips, 0},
		{"attribute string", `#[doc = "allow ignore"]`, modeSuppressions, 0},
		{"raw attribute string", `#[doc = r##"" allow ignore"##]`, modeSuppressions, 0},
		{"attribute comment", `#[cfg(/* allow ignore */ test)]`, modeSuppressions, 0},
		{"lifetime before attribute", "'a\n#[ignore]", modeTestSkips, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := rustFindings("fixture.rs", []byte(test.source), test.mode)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestRustLexicalBoundaries(t *testing.T) {
	t.Parallel()
	errorCases := []string{
		"/*",
		"#[",
		"#[/*",
		"#[\"unterminated",
	}
	for _, source := range errorCases {
		if _, err := rustAttributes([]byte(source)); err == nil {
			t.Errorf("rustAttributes(%q) accepted malformed source", source)
		}
	}
	validCases := []string{
		"#",
		"// comment\n#[test]",
		"/* outer /* nested */ comment */ #[test]",
		"#[cfg([nested])]",
	}
	for _, source := range validCases {
		if _, err := rustAttributes([]byte(source)); err != nil {
			t.Errorf("rustAttributes(%q) error = %v", source, err)
		}
	}
	characterCases := []string{
		"'",
		"'a",
		"'a'",
		"'🦀'",
		"'\\n'",
		"'\\",
	}
	for _, source := range characterCases {
		end, _ := skipRustCharacter([]byte(source), 0, 1)
		if end <= 0 || end > len(source) {
			t.Errorf("skipRustCharacter(%q) = %d", source, end)
		}
	}
	stringCases := []string{
		`"ordinary"`,
		"\"escaped\\\"quote\"",
		"\"line\nbreak\"",
		`"unterminated`,
	}
	for _, source := range stringCases {
		end, _ := skipRustString([]byte(source), 0, 1)
		if end != len(source) {
			t.Errorf("skipRustString(%q) = %d, want %d", source, end, len(source))
		}
	}
}

func TestClippySuppressionShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		valid bool
	}{
		{`#[expect(clippy::unwrap_used, reason = "checked invariant")]`, true},
		{`#![allow(clippy::unwrap_used, reason = "crate scope")]`, false},
		{`#[allow(clippy::all, reason = "blanket")]`, false},
		{`#[allow(clippy::UPPER, reason = "invalid rule")]`, false},
		{`#[allow(clippy::unwrap_used)]`, false},
		{`#[allow(clippy::unwrap_used, reason = "")]`, false},
		{`#[cfg_attr(all(), allow(clippy::unwrap_used))]`, false},
	}
	for _, test := range tests {
		if validClippySuppression(test.value) != test.valid {
			t.Errorf("validClippySuppression(%q) != %t", test.value, test.valid)
		}
	}
}
