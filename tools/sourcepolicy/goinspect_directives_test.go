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

func TestGoLinknameIsRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		filepath.Join(root, "main.go"): "package main\n\nfunc main() {}\n",
		path: "package main\n\nimport (\n\t_ \"unsafe\"\n\t\"testing\"\n)\n\n" +
			"//go:linkname linkedMain main.main\n" +
			"func linkedMain()\n\n" +
			"func TestEntry(t *testing.T) { linkedMain() }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{"main.go", "main_test.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not use go:linkname") {
		t.Fatalf("findings = %v, want go:linkname rejection", findings)
	}
}
