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
	"slices"
	"strings"
	"testing"
)

func TestArchitectureOwnsProtocolAtFinalPath(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !slices.Contains(policy.Packages, "internal/operation/urlreference/protocol") {
		t.Fatal("final protocol package is not governed")
	}
	if !slices.Contains(policy.ProhibitedPaths, "internal/workerprotocolv1") {
		t.Fatal("obsolete protocol package can be recreated")
	}
}

func TestArchitectureOwnsAdmissionAtFinalPath(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !slices.Contains(policy.Packages, "internal/operation/urlreference/admission") {
		t.Fatal("final admission package is not governed")
	}
	if !slices.Contains(policy.ProhibitedPaths, "internal/urladmission") {
		t.Fatal("obsolete admission package can be recreated")
	}
}

func TestArchitectureOwnsAttemptAtFinalPath(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !slices.Contains(policy.Packages, "internal/operation/urlreference/attempt") {
		t.Fatal("final attempt-evidence package is not governed")
	}
	if !slices.Contains(policy.ProhibitedPaths, "internal/attemptstore") {
		t.Fatal("obsolete attempt-evidence package can be recreated")
	}
}

func TestArchitectureOwnsOperationAtFinalPath(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !slices.Contains(policy.Packages, "internal/operation/urlreference") {
		t.Fatal("final URL-reference operation root is not governed")
	}
	if !slices.Contains(policy.ProhibitedPaths, "internal/urloperation") {
		t.Fatal("obsolete URL-reference operation can be recreated")
	}
}

func TestArchitectureSourceOwnership(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	tests := map[string]struct {
		file string
		want bool
	}{
		"undeclared attempt":  {file: "internal/operation/urlreference/attempt/native.c", want: true},
		"declared Java":       {file: "tools/sourcepolicy/Main.java"},
		"declared worker":     {file: "worker/url-reference/data.bin"},
		"command data":        {file: "cmd/rogue/data.json", want: true},
		"native source":       {file: "tools/rogue/main.c", want: true},
		"nested native":       {file: "tools/sourcepolicy/rogue/main.c", want: true},
		"nested Go assembly":  {file: "tools/sourcepolicy/rogue/main.s", want: true},
		"nested Objective-C":  {file: "tools/sourcepolicy/rogue/main.m", want: true},
		"nested Fortran":      {file: "tools/sourcepolicy/rogue/main.f90", want: true},
		"nested SWIG":         {file: "tools/sourcepolicy/rogue/main.swig", want: true},
		"nested SWIG C++":     {file: "tools/sourcepolicy/rogue/main.swigcxx", want: true},
		"nested Java":         {file: "tools/sourcepolicy/rogue/Main.java", want: true},
		"Go object":           {file: "tools/sourcepolicy/injected.syso", want: true},
		"worker Rust":         {file: "worker/url-reference/src/main.rs"},
		"worker build script": {file: "worker/url-reference/build.rs", want: true},
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

func TestArchitectureRejectsWindowsInvalidPaths(t *testing.T) {
	t.Parallel()

	for _, file := range []string{
		`tools/sourcepolicy/rogue\file.go`,
		"tools/sourcepolicy/trailing./file.go",
		"tools/sourcepolicy/trailing /file.go",
		"tools/sourcepolicy/aux.go",
		"tools/sourcepolicy/COM1.txt",
		"docs/COM¹.txt",
		"docs/LPT².txt",
		"tools/sourcepolicy/bad:name.go",
	} {
		findings := architecturePathFindings(
			[]string{file}, nil, validArchitectureFixturePolicy(),
		)
		if len(findings) != 1 || !strings.Contains(findings[0], "invalid tracked path") {
			t.Fatalf("%q findings = %v", file, findings)
		}
	}
}

func TestArchitectureRejectsCaseCollisions(t *testing.T) {
	t.Parallel()

	for _, files := range [][]string{
		{"docs/contracts/cel_struct_001.json", "docs/contracts/CEL_STRUCT_001.json"},
		{"docs/k.txt", "docs/K.txt"},
	} {
		findings := architecturePathFindings(files, nil, validArchitectureFixturePolicy())
		if len(findings) != 1 || !strings.Contains(findings[0], "collides") {
			t.Fatalf("findings = %v", findings)
		}
	}
}
