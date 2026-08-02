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
	"slices"
	"testing"
)

var cargoLintCases = []struct {
	name     string
	source   string
	findings int
}{
	{"Clippy string", "[lints.clippy]\nall = \"allow\"\n", 1},
	{
		"Clippy table",
		"[workspace.lints.clippy]\nneedless_return = { level = \"allow\" }\n",
		1,
	},
	{"Rust allow", "[lints.rust]\nunsafe_code = \"allow\"\n", 1},
	{
		"Rustdoc allow",
		"[lints.rustdoc]\nbroken_intra_doc_links = \"allow\"\n",
		1,
	},
	{
		"Cargo allow",
		"[workspace.lints.cargo]\nunknown_lints = \"allow\"\n",
		1,
	},
	{
		"custom tool allow",
		"[lints.custom]\nrule = \"allow\"\n",
		1,
	},
	{"deny", "[workspace.lints.clippy]\nall = \"deny\"\n", 0},
	{"workspace inheritance", "[lints]\nworkspace = true\n", 0},
	{
		"explicit tests",
		"[package]\nname = \"fixture\"\nautotests = false\n",
		0,
	},
	{
		"automatic library disabled",
		"[package]\nname = \"fixture\"\nautolib = false\n",
		0,
	},
	{
		"explicit binaries",
		"[package]\nname = \"fixture\"\nautobins = false\n",
		0,
	},
	{
		"automatic examples disabled",
		"[package]\nname = \"fixture\"\nautoexamples = false\n",
		0,
	},
	{
		"automatic benches disabled",
		"[package]\nname = \"fixture\"\nautobenches = false\n",
		0,
	},
	{"target tests disabled", "[[bin]]\nname = \"fixture\"\ntest = false\n", 1},
	{"doctests disabled", "[lib]\ndoctest = false\n", 1},
	{"library target", "[lib]\npath = \"src/library.rs\"\n", 1},
	{"custom harness", "[[test]]\nname = \"fixture\"\nharness = false\n", 1},
	{
		"feature-gated test",
		"[[test]]\nname = \"fixture\"\nrequired-features = [\"hidden\"]\n",
		1,
	},
	{"package features", "[features]\nhidden = []\n", 1},
	{
		"optional dependency",
		"[dependencies]\nfixture = { version = \"1\", optional = true }\n",
		1,
	},
	{
		"target optional dependency",
		"[target.'cfg(windows)'.dev-dependencies]\n" +
			"fixture = { version = \"1\", optional = true }\n",
		1,
	},
	{
		"workspace optional dependency",
		"[workspace.dependencies]\n" +
			"fixture = { version = \"1\", optional = true }\n",
		1,
	},
	{
		"required dependency",
		"[dependencies]\nfixture = { version = \"1\" }\n",
		0,
	},
	{"test profile", "[profile.test]\ndebug-assertions = false\n", 1},
	{"ordinary target", "[[test]]\nname = \"fixture\"\npath = \"tests/fixture.rs\"\n", 0},
	{"patch", "[patch.crates-io]\nfixture = { path = \"../fixture\" }\n", 1},
	{"replace", "[replace]\n\"fixture:1.0.0\" = { path = \"../fixture\" }\n", 1},
	{"unrelated", "[package]\nname = \"fixture\"\n", 0},
	{"malformed", "[lints.clippy\n", 1},
}

func TestCargoLintAllowances(t *testing.T) {
	t.Parallel()
	for _, test := range cargoLintCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := cargoLintFindings(
				"Cargo.toml",
				[]byte(test.source),
			)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestCargoWorkspaceInventory(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"Cargo.toml": `[workspace]
members = ["worker/url-reference"]
exclude = ["worker/qualification-fixtures"]
`,
		"worker/url-reference/Cargo.toml":          "[package]\n",
		"worker/qualification-fixtures/Cargo.toml": "[package]\n",
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	readFile := func(path string) ([]byte, error) {
		return []byte(files[path]), nil
	}
	if findings := cargoWorkspaceInventoryFindings(paths, readFile); len(findings) != 0 {
		t.Fatalf("valid inventory findings = %v", findings)
	}
	paths = append(paths, "hidden/Cargo.toml")
	if findings := cargoWorkspaceInventoryFindings(paths, readFile); len(findings) != 1 {
		t.Fatalf("hidden manifest findings = %v, want 1", findings)
	}
	files["Cargo.toml"] = "[workspace]\nmembers = []\nexclude = []\n"
	if findings := cargoWorkspaceInventoryFindings(paths[:3], readFile); len(findings) != 2 {
		t.Fatalf("workspace mismatch findings = %v, want 2", findings)
	}
	if findings := cargoWorkspaceInventoryFindings(
		[]string{"Cargo.toml"},
		func(string) ([]byte, error) { return nil, errors.New("read failure") },
	); len(findings) != 1 {
		t.Fatalf("read findings = %v, want 1", findings)
	}
	if findings := cargoWorkspaceInventoryFindings(nil, readFile); len(findings) != 1 {
		t.Fatalf("missing workspace findings = %v, want 1", findings)
	}
	if cargoStringListEquals([]any{"one", 2}, []string{"one", "two"}) {
		t.Fatal("mixed Cargo string list accepted")
	}
}

func TestCargoLibraryInventory(t *testing.T) {
	files := map[string]string{
		"Cargo.toml": `[workspace]
members = ["worker/url-reference"]
exclude = ["worker/qualification-fixtures"]
`,
		"worker/url-reference/Cargo.toml":          "[package]\n",
		"worker/qualification-fixtures/Cargo.toml": "[package]\n",
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	readFile := func(path string) ([]byte, error) {
		source, exists := files[path]
		if !exists {
			return nil, errors.New("missing fixture")
		}
		return []byte(source), nil
	}
	tests := []struct {
		name     string
		path     string
		findings int
	}{
		{"member library", "worker/url-reference/src/lib.rs", 1},
		{"case variant", "worker/url-reference/SRC/LIB.RS", 1},
		{"unrelated path", "docs/fixture/src/lib.rs", 0},
		{"virtual root", "src/lib.rs", 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := append(slices.Clone(paths), test.path)
			findings := cargoWorkspaceInventoryFindings(inventory, readFile)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
	files["Cargo.toml"] = "[package]\nname = \"root\"\n"
	inventory := append(slices.Clone(paths), "src/lib.rs")
	if findings := cargoWorkspaceInventoryFindings(
		inventory,
		readFile,
	); len(findings) != 2 {
		t.Fatalf("root package findings = %v, want 2", findings)
	}
}
