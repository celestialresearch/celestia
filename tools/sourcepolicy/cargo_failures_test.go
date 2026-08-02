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

func TestCargoOptionalDependencyShapes(t *testing.T) {
	tests := []struct {
		name     string
		document map[string]any
		optional bool
	}{
		{"empty", map[string]any{}, false},
		{"scalar dependency", map[string]any{"dependencies": "invalid"}, false},
		{"empty dependency", map[string]any{"dependencies": map[string]any{}}, false},
		{"non-table dependency", map[string]any{
			"dependencies": map[string]any{"crate": "1"},
		}, false},
		{"ordinary dependency", map[string]any{
			"dependencies": map[string]any{
				"crate": map[string]any{"version": "1"},
			},
		}, false},
		{"optional dependency", map[string]any{
			"dependencies": map[string]any{
				"crate": map[string]any{"optional": true},
			},
		}, true},
		{"workspace optional", map[string]any{
			"workspace": map[string]any{
				"dependencies": map[string]any{
					"crate": map[string]any{"optional": true},
				},
			},
		}, true},
		{"target scalar", map[string]any{"target": "invalid"}, false},
		{"target non-table", map[string]any{
			"target": map[string]any{"cfg(any())": "invalid"},
		}, false},
		{"target optional", map[string]any{
			"target": map[string]any{
				"cfg(any())": map[string]any{
					"dependencies": map[string]any{
						"crate": map[string]any{"optional": true},
					},
				},
			},
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cargoOptionalDependency(test.document); got != test.optional {
				t.Fatalf("cargoOptionalDependency() = %t, want %t", got, test.optional)
			}
		})
	}
}

func TestCargoWorkspaceMalformedShapes(t *testing.T) {
	read := func(source string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(source), nil }
	}
	tests := []struct {
		name     string
		source   string
		findings int
	}{
		{"malformed", "[workspace", 0},
		{"missing workspace", "[package]\nname = \"fixture\"", 1},
		{"scalar members", "[workspace]\nmembers = \"worker/url-reference\"\nexclude = [\"worker/qualification-fixtures\"]", 1},
		{"scalar exclusion", "[workspace]\nmembers = [\"worker/url-reference\"]\nexclude = true", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := cargoWorkspaceInventoryFindings(
				[]string{
					"Cargo.toml",
					"worker/qualification-fixtures/Cargo.toml",
					"worker/url-reference/Cargo.toml",
				},
				read(test.source),
			)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestLintLevelShapes(t *testing.T) {
	tests := []struct {
		value any
		want  string
	}{
		{nil, ""},
		{true, ""},
		{map[string]any{}, ""},
		{map[string]any{"level": true}, ""},
		{map[string]any{"level": "WARN"}, "warn"},
	}
	for _, test := range tests {
		if got := lintLevel(test.value); got != test.want {
			t.Errorf("lintLevel(%v) = %q, want %q", test.value, got, test.want)
		}
	}
}
