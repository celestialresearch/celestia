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

func TestGoPolicyRejectsNativeSource(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "native_test.go")
	nativePath := filepath.Join(root, "call_amd64.s")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"func TestNative(t *testing.T) {}\n",
		nativePath: "TEXT ·entry(SB),$0-0\n\tRET\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath), filepath.Base(nativePath)},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err == nil || !strings.Contains(err.Error(), "native source") {
		t.Fatalf("native-source error = %v", err)
	}
}

func TestGoPolicyIgnoresUnrelatedNativeSource(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "fixture", "ordinary_test.go")
	nativePath := filepath.Join(root, "other", "ordinary.h")
	if err := os.MkdirAll(filepath.Dir(testPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(nativePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"func TestOrdinary(t *testing.T) {}\n",
		nativePath: "#define ORDINARY 1\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{
			filepath.Join("fixture", "ordinary_test.go"),
			filepath.Join("other", "ordinary.h"),
		},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
}
