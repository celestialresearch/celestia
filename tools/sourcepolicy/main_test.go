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
	"os"
	"path/filepath"
	"testing"
)

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
		{"ordinary test", `t.Log("verified")`, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "fixture_test.go")
			source := "package fixture\n\nimport \"testing\"\n\n" +
				"func TestFixture(t *testing.T) {\n" + test.call + "\n}\n"
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			findings := goSkipFindings(path)
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
