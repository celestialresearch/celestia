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

func TestRustFindingsMalformedBoundaries(t *testing.T) {
	tests := []struct {
		source   string
		findings int
	}{
		{"/*", 1},
		{"#[", 1},
		{`r##"unterminated`, 0},
		{"macro!([ignore", 1},
		{")", 0},
	}
	for _, test := range tests {
		findings := rustFindings(
			"fixture.rs",
			[]byte(test.source),
			modeTestSkips,
		)
		if len(findings) != test.findings {
			t.Fatalf(
				"rustFindings(%q) = %v, want %d",
				test.source,
				findings,
				test.findings,
			)
		}
	}
}
