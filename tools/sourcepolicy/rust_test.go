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
		"automatic tests disabled",
		"[package]\nname = \"fixture\"\nautotests = false\n",
		1,
	},
	{
		"automatic library disabled",
		"[package]\nname = \"fixture\"\nautolib = false\n",
		1,
	},
	{
		"automatic binaries disabled",
		"[package]\nname = \"fixture\"\nautobins = false\n",
		1,
	},
	{
		"automatic examples disabled",
		"[package]\nname = \"fixture\"\nautoexamples = false\n",
		1,
	},
	{
		"automatic benches disabled",
		"[package]\nname = \"fixture\"\nautobenches = false\n",
		1,
	},
	{"target tests disabled", "[[bin]]\nname = \"fixture\"\ntest = false\n", 1},
	{"doctests disabled", "[lib]\ndoctest = false\n", 1},
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

func TestCargoConfigurationAllowances(t *testing.T) {
	t.Parallel()
	for _, test := range cargoConfigurationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := cargoConfigFindings(
				".cargo/config.toml",
				[]byte(test.source),
			)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func cargoConfigurationCases() []struct {
	name     string
	source   string
	findings int
} {
	return []struct {
		name     string
		source   string
		findings int
	}{
		{"array allow", `[build]` + "\n" + `rustflags = ["-A", "clippy::all"]`, 1},
		{"compact allow", `[build]` + "\n" + `rustflags = ["-Aclippy::all"]`, 1},
		{"long allow", `[build]` + "\n" + `rustflags = "--allow warnings"`, 1},
		{
			"target cap",
			`[target.x86_64-pc-windows-msvc]` + "\n" +
				`rustflags = ["--cap-lints=allow"]`,
			1,
		},
		{"warn cap", `[build]` + "\n" + `rustflags = ["--cap-lints=warn"]`, 1},
		{"deny cap", `[build]` + "\n" + `rustflags = ["--cap-lints", "deny"]`, 1},
		{
			"array table override",
			`[[target]]` + "\n" + `runner = "untrusted"`,
			1,
		},
		{
			"rustdoc allow",
			`[build]` + "\n" + `rustdocflags = ["--allow=warnings"]`,
			1,
		},
		{"response file", `[build]` + "\n" + `rustflags = ["@args.txt"]`, 1},
		{"included config", `include = ["hostile.toml"]`, 1},
		{"command alias", `[alias]` + "\n" + `clippy = "bypass"`, 1},
		{
			"credential alias",
			`[credential-alias]` + "\n" + `private = ["credential.exe"]`,
			1,
		},
		{"source paths", `paths = ["../override"]`, 1},
		{"environment", `[env]` + "\n" + `RUSTFLAGS = "--cap-lints=allow"`, 1},
		{"source table", `[source.crates-io]` + "\n" + `replace-with = "mirror"`, 1},
		{
			"test profile",
			`[profile.test]` + "\n" + `debug-assertions = false`,
			1,
		},
		{"build warnings", `[build]` + "\n" + `warnings = "allow"`, 1},
		{"build target", `[build]` + "\n" + `target = "wasm32-unknown-unknown"`, 1},
		{
			"cfg injection",
			`[build]` + "\n" + `rustflags = ["--cfg", "skip_tests"]`,
			1,
		},
		{"rustc wrapper", `[build]` + "\n" + `rustc-wrapper = "wrapper.exe"`, 1},
		{
			"workspace wrapper",
			`[build]` + "\n" + `rustc-workspace-wrapper = "wrapper.exe"`,
			1,
		},
		{"rustc override", `[build]` + "\n" + `rustc = "rustc-proxy.exe"`, 1},
		{
			"target runner",
			`[target.x86_64-pc-windows-msvc]` + "\n" +
				`runner = "runner.exe"`,
			1,
		},
		{
			"target linker",
			`[target.x86_64-pc-windows-msvc]` + "\n" +
				`linker = "linker.exe"`,
			1,
		},
		{"linker", `[build]` + "\n" + `rustflags = ["-C", "link-arg=/Brepro"]`, 0},
		{"linker string", `[build]` + "\n" + `rustflags = "-C link-arg=/Brepro"`, 0},
		{"empty rustdoc flags", `[build]` + "\n" + `rustdocflags = []`, 0},
		{"malformed", `[build` + "\n", 1},
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
			"dynamic suppression",
			`macro_rules! lint { ($level:ident) => { #[$level(clippy::all)] fn f() {} } }`,
			modeSuppressions,
			1,
		},
		{
			"reasoned allow",
			`#[allow(clippy::needless_pass_by_value, reason = "FFI owns the value")]`,
			modeSuppressions,
			0,
		},
		{"comment", "// #[ignore]\nfn test() {}", modeTestSkips, 0},
		{"string", `const VALUE: &str = "#[ignore]";`, modeTestSkips, 0},
		{"include", `include!("skipped.inc");`, modeTestSkips, 1},
		{"include alias", `use std::include as load;`, modeTestSkips, 1},
		{
			"include forwarding",
			`macro_rules! load { ($path:expr) => { include!($path) } }`,
			modeTestSkips,
			1,
		},
		{"path module", `#[path = "skipped.inc"] mod skipped;`, modeTestSkips, 1},
		{
			"conditional path",
			`#[cfg_attr(all(), path = "skipped.inc")] mod skipped;`,
			modeTestSkips,
			1,
		},
		{
			"forwarded ignore",
			`macro_rules! make_test {
				($attribute:meta) => { #[test] #[$attribute] fn generated() {} };
			}
			make_test!(ignore);`,
			modeTestSkips,
			1,
		},
		{"include comment", `// include!("skipped.inc");`, modeTestSkips, 0},
		{"include string", `const VALUE: &str = "include!(ignored)";`, modeTestSkips, 0},
		{"include function", `fn include(value: u8) -> u8 { value }`, modeTestSkips, 0},
		{
			"ordinary include alias",
			`use helper::call as include; fn invoke() { include(); }`,
			modeTestSkips,
			0,
		},
		{"ignore function", `fn ignore(value: bool) -> bool { value }`, modeTestSkips, 0},
		{
			"ignore macro expression",
			`fn ignore() {} fn invoke() { evaluate!(ignore()); }`,
			modeTestSkips,
			0,
		},
		{"cfg path predicate", `#[cfg(path)] fn selected() {}`, modeTestSkips, 0},
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

func TestRustDocumentationExit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		findings int
	}{
		{
			"documentation exit",
			"/// ```\n/// std::process::exit(0);\n/// ```",
			1,
		},
		{
			"split documentation exit",
			"/*!\nexit\n(\n0\n);\n*/",
			1,
		},
		{
			"aliased documentation exit",
			"/// use std::process::exit as done;\n/// done(0);",
			1,
		},
		{
			"multiline braced alias",
			"/// ```rust\n/// use std::process::{\n/// exit as done,\n/// };\n/// done(0);\n/// ```",
			1,
		},
		{
			"visibility import",
			"/// ```rust\n/// pub(crate) use std::process::{exit as done};\n/// done(0);\n/// ```",
			1,
		},
		{
			"attributed import",
			"/// ```rust\n/// #[allow(unused_imports)] use std::process::{exit as done};\n/// done(0);\n/// ```",
			1,
		},
		{
			"parenthesised documentation exit",
			"/// (std::process::exit)(0);",
			1,
		},
		{
			"nested block comment",
			"/**\n```rust\n/* std::process::exit(0); */\nassert!(true);\n```\n*/",
			0,
		},
		{
			"nested markers in string",
			"/**\n```rust\nlet open = \"/*\";\nstd::process::exit(0);\nlet close = \"*/\";\n```\n*/",
			1,
		},
		{
			"nested block documentation exit",
			"/**\n```rust\n/* nested */\nstd::process::exit(0);\n```\n*/",
			1,
		},
		{"ordinary exit prose", "/// The exit status is retained.", 0},
		{"colon exit prose", "/// Failure: exit status is retained.", 0},
		{"use exit prose", "/// Callers use exit status for diagnostics.", 0},
		{
			"multiline use exit prose",
			"/// Callers can\n/// use exit status for diagnostics.",
			0,
		},
		{"punctuated use exit prose", "/// Guidance: use exit status;", 0},
		{"doc attribute", `#[doc = "ordinary"]`, 1},
		{"doc include", `#![doc = include_str!("README.md")]`, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := rustFindings(
				"fixture.rs", []byte(test.source), modeTestSkips,
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
	if cargoStringListEquals([]any{"one", 2}, []string{"one", "two"}) {
		t.Fatal("mixed Cargo string list accepted")
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
