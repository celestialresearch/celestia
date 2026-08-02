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
	"strings"
	"testing"
)

func TestGoPolicyRejectsUngovernedBuildTags(t *testing.T) {
	tests := []struct {
		name      string
		directive string
	}{
		{"custom", "//go:build privatecheck"},
		{"modern tab", "//go:build\tprivatecheck"},
		{"legacy tab", "// +build\tprivatecheck"},
		{"future release", "//go:build go1.999"},
		{"alternate compiler", "//go:build gccgo"},
		{"architecture feature", "//go:build amd64.v2"},
		{"negated", "//go:build !privatecheck"},
		{"and right", "//go:build linux && privatecheck"},
		{"and left", "//go:build privatecheck && linux"},
		{"or right", "//go:build linux || privatecheck"},
		{"or left", "//go:build privatecheck || linux"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			testPath := filepath.Join(root, "feature_test.go")
			writeGoPolicyFixture(t, root, map[string]string{
				testPath: test.directive + "\n\npackage fixture\n\n" +
					"import \"testing\"\n\nfunc TestFeature(t *testing.T) {}\n",
			})
			t.Chdir(root)
			_, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Base(testPath)},
				os.ReadFile,
				[]buildTarget{{goos: "linux", goarch: "amd64"}},
			)
			if err == nil ||
				!strings.Contains(err.Error(), "ungoverned Go build constraints") {
				t.Fatalf("build-tag error = %v", err)
			}
		})
	}
}

func TestGoPolicyIgnoresBuildTextAfterPackage(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"//go:build privatecheck\n" +
			"func TestFeature(t *testing.T) {}\n",
	})
	t.Chdir(root)
	if _, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	); err != nil {
		t.Fatal(err)
	}
}

func TestGoPolicyIgnoresDirectiveShapedPackageDocs(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "// +build privatecheck\npackage fixture\n\n" +
			"import \"testing\"\n\nfunc TestFeature(t *testing.T) {}\n",
	})
	t.Chdir(root)
	if _, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	); err != nil {
		t.Fatalf("legacy package documentation: %v", err)
	}
}

func TestGoPolicyIgnoresLegacyBuildBeforeBlockDoc(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "// +build privatecheck\n/* package documentation */\n\n" +
			"package fixture\n\nimport \"testing\"\n\nfunc TestFeature(t *testing.T) {}\n",
	})
	t.Chdir(root)
	if _, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	); err != nil {
		t.Fatalf("legacy package documentation: %v", err)
	}
}

func TestGoPolicyRejectsMultipleGoBuildComments(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "//go:build linux\n//go:build amd64\n\npackage fixture\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	)
	if err == nil || !strings.Contains(err.Error(), "multiple //go:build comments") {
		t.Fatalf("multiple go:build error = %v", err)
	}
}

func TestGoPolicyRejectsBOMLegacyBuild(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "\ufeff// +build privatecheck\n\npackage fixture\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	)
	if err == nil || !strings.Contains(err.Error(), "ungoverned Go build constraints") {
		t.Fatalf("BOM legacy build error = %v", err)
	}
}

func TestGoPolicyTreatsAdjacentGoBuildAsConstraint(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "//go:build privatecheck\npackage fixture\n\n" +
			"import \"testing\"\n\nfunc TestFeature(t *testing.T) {}\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	)
	if err == nil || !strings.Contains(err.Error(), "ungoverned Go build constraints") {
		t.Fatalf("adjacent go:build error = %v", err)
	}
}
