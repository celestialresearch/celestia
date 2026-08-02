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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoPolicyInspectsImportedHelpers(t *testing.T) {
	root := t.TempDir()
	helperDirectory := filepath.Join(root, "helper")
	if err := os.Mkdir(helperDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(helperDirectory, "helper.go")
	testPath := filepath.Join(root, "root_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		helperPath: "package helper\n\nimport \"testing\"\n\n" +
			"func Skip(t *testing.T) { t.Skip(\"hidden\") }\n",
		testPath: "package fixture\n\nimport (\n" +
			"\t\"testing\"\n" +
			"\t\"fixture.invalid/sourcepolicy/helper\"\n" +
			")\n\n" +
			"func TestEntry(t *testing.T) { helper.Skip(t) }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{
			filepath.Base(testPath),
			filepath.Join("helper", filepath.Base(helperPath)),
		},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want imported helper skip", findings)
	}
}

func TestGoPolicyRejectsNestedModules(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	testPath := filepath.Join(root, "root_test.go")
	helperPath := filepath.Join(nested, "helper.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport (\n" +
			"\t\"testing\"\n\t\"fixture.invalid/nested\"\n)\n\n" +
			"func TestEntry(t *testing.T) { nested.Skip(t) }\n",
		helperPath: "package nested\n\nimport \"testing\"\n\n" +
			"func Skip(t *testing.T) { t.Skip(\"hidden\") }\n",
		filepath.Join(nested, "go.mod"): "module fixture.invalid/nested\n\ngo 1.26.5\n",
	})
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n\n"+
			"require fixture.invalid/nested v0.0.0\n\n"+
			"replace fixture.invalid/nested => ./nested\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{"root_test.go", "nested/go.mod", "nested/helper.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err == nil || !strings.Contains(err.Error(), "nested Go modules") {
		t.Fatalf("nested-module error = %v", err)
	}
}

func TestGoPolicyPrevalidatesHelpers(t *testing.T) {
	failure := errors.New("invalid helper source")
	_, err := goPackageSkipFindingsWithTargets(
		[]string{"root_test.go", "helper/helper.go"},
		func(path string) ([]byte, error) {
			if path == "helper/helper.go" {
				return nil, failure
			}
			return []byte("package fixture\n"), nil
		},
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want helper validation failure", err)
	}
}
