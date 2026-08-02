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
	"runtime"
	"strings"
	"testing"
)

func TestGoCGOSkip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cgo_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		path: "//go:build cgo\n\npackage fixture\n\n" +
			"import \"testing\"\n\n" +
			"func TestFixture(t *testing.T) { t.Skip(\"disabled\") }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(path)},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH, cgo: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want one CGO skip", findings)
	}
}

func TestGoPolicyRejectsCGOInTestedPackage(t *testing.T) {
	root := t.TempDir()
	nativePath := filepath.Join(root, "native.go")
	testPath := filepath.Join(root, "native_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		nativePath: "package fixture\n\n/* int fixture(void) { return 1; } */\n" +
			"import \"C\"\n",
		testPath: "package fixture\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n" +
			"func TestFixture(t *testing.T) { os.Exit(0) }\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(nativePath), filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "aix", goarch: "ppc64"}},
	)
	if err == nil || !strings.Contains(err.Error(), "cgo is unsupported") {
		t.Fatalf("cgo error = %v", err)
	}
}
