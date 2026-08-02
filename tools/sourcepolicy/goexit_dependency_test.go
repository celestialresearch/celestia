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

func TestGoKnownDependencyExit(t *testing.T) {
	root := t.TempDir()
	dependency := filepath.Join(root, "logrus")
	writeGoPolicyFixture(t, root, map[string]string{
		"exit_test.go": "package fixture\n\n" +
			"import (\"testing\"; \"github.com/sirupsen/logrus\")\n" +
			"func init() { logrus.Exit(0) }\n" +
			"func TestFailure(t *testing.T) { t.Fatal(\"must run\") }\n",
		filepath.Join(dependency, "logrus.go"): "package logrus\nfunc Exit(int) {}\n",
	})
	if err := os.WriteFile(
		filepath.Join(dependency, "go.mod"),
		[]byte("module github.com/sirupsen/logrus\n\ngo 1.26.5\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n\n"+
			"require github.com/sirupsen/logrus v0.0.0\n"+
			"replace github.com/sirupsen/logrus => ./logrus\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{"exit_test.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not exit successfully") {
		t.Fatalf("findings = %v, want dependency exit rejection", findings)
	}
}
