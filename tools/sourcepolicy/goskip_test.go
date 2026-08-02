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
		{"formatted receiver", `t.Skipf("%s", "unverified")`, 1},
		{"renamed receiver", `testCase.SkipNow()`, 1},
		{"method expression", `(*testing.T).Skip(t, "unverified")`, 1},
		{
			"custom method",
			`cursor{}.Skip(1)`,
			0,
		},
		{
			"custom function field",
			`fields{}.Skip("ordinary")`,
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
				"type fields struct { Skip func(...any) }\n\n" +
				"type cursorContract interface {\n" +
				"\tSkip(int)\n" +
				"\tSkipf(int, ...any)\n" +
				"\tSkipNow() int\n" +
				"}\n" +
				"func useCursor(value cursorContract) {\n" +
				"\tvalue.Skip(1)\n" +
				"\tvalue.Skipf(1)\n" +
				"\t_ = value.SkipNow()\n" +
				"}\n\n" +
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

func TestGoSkipAcrossFiles(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "helper.go")
	caller := filepath.Join(root, "caller_test.go")
	linux := filepath.Join(root, "platform_linux.go")
	windows := filepath.Join(root, "platform_windows.go")
	sources := map[string][]byte{
		helper: []byte(
			"package fixture\n\nimport \"testing\"\n\n" +
				"func testContext(t *testing.T) *testing.T { return t }\n" +
				"type skipper interface {\n" +
				"\tSkip(...any)\n" +
				"\tSkipf(string, ...any)\n" +
				"\tSkipNow()\n" +
				"}\n" +
				"func hideSkip(value skipper) {\n" +
				"\tvalue.Skip(\"disabled\")\n" +
				"\tvalue.Skipf(\"%s\", \"disabled\")\n" +
				"\tvalue.SkipNow()\n" +
				"}\n",
		),
		caller: []byte(
			"package fixture\n\nimport \"testing\"\n\n" +
				"func TestFixture(t *testing.T) {\n" +
				"\ttestContext(t).Skip(\"disabled\")\n" +
				"\thideSkip(t)\n}\n",
		),
		linux: []byte(
			"//go:build linux\n\npackage fixture\n\nconst platform = \"linux\"\n",
		),
		windows: []byte(
			"//go:build windows\n\npackage fixture\n\nconst platform = \"windows\"\n",
		),
	}
	for path, source := range sources {
		if err := os.WriteFile(path, source, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{
			filepath.Base(helper),
			filepath.Base(caller),
			filepath.Base(linux),
			filepath.Base(windows),
		},
		os.ReadFile,
		[]buildTarget{
			{goos: "linux", goarch: "amd64"},
			{goos: "windows", goarch: "amd64"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings = %v, want four", findings)
	}
}
