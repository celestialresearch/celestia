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

import "testing"

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
