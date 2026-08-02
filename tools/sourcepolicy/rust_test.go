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
	"strings"
	"testing"
)

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

func TestRustPolicyRejectsForwardedInclude(t *testing.T) {
	t.Parallel()

	source := []byte(`macro_rules! load {
    ($macro_name:ident) => { $macro_name!("owned.rs") }
}
load!(include);`)
	findings := rustFindings("fixture.rs", source, modeTestSkips)
	if len(findings) != 1 || !strings.Contains(findings[0], "Rust include! is prohibited") {
		t.Fatalf("findings = %v", findings)
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
