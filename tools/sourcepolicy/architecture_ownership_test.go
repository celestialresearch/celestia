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

func TestArchitectureSourceOwnership(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	tests := map[string]struct {
		file string
		want bool
	}{
		"declared internal":   {file: "internal/attemptstore/native.c"},
		"declared Java":       {file: "tools/sourcepolicy/Main.java"},
		"declared worker":     {file: "worker/url-reference/data.bin"},
		"command data":        {file: "cmd/rogue/data.json", want: true},
		"native source":       {file: "tools/rogue/main.c", want: true},
		"nested native":       {file: "tools/sourcepolicy/rogue/main.c", want: true},
		"nested Java":         {file: "tools/sourcepolicy/rogue/Main.java", want: true},
		"worker Rust":         {file: "worker/url-reference/src/main.rs"},
		"worker Java":         {file: "worker/url-reference/rogue/Main.java", want: true},
		"documentation Go":    {file: "docs/example.go", want: true},
		"workflow JavaScript": {file: ".github/workflows/action.js", want: true},
		"root fixture Go":     {file: "testdata/fixture.go", want: true},
		"script data":         {file: ".github/scripts/rogue.txt", want: true},
		"worker data":         {file: "worker/rogue/data.bin", want: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			findings := architecturePathFindings([]string{test.file}, nil, policy)
			if got := len(findings) != 0; got != test.want {
				t.Fatalf("findings = %v, want rejection %t", findings, test.want)
			}
		})
	}
}

func TestArchitectureEscapesInvalidPaths(t *testing.T) {
	t.Parallel()

	for _, file := range []string{
		"tools/sourcepolicy/rogue\nforged.go",
		"tools/sourcepolicy/rogue\x1b[2J.go",
		"tools/sourcepolicy/rogue\u2028forged.go",
	} {
		findings := architecturePathFindings(
			[]string{file}, nil, validArchitectureFixturePolicy(),
		)
		if len(findings) != 1 || strings.ContainsAny(findings[0], "\n\r\x1b\u2028") {
			t.Fatalf("unsafe diagnostic = %q", findings)
		}
	}
}

func TestArchitectureRejectsExecutableRootFile(t *testing.T) {
	t.Parallel()

	findings := architecturePathFindings(
		[]string{"README.md"},
		map[string]struct{}{"README.md": {}},
		validArchitectureFixturePolicy(),
	)
	if len(findings) != 1 || findings[0] != "README.md: script is not declared" {
		t.Fatalf("findings = %v", findings)
	}
}
