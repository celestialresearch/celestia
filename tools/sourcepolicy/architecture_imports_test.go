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
	"fmt"
	"strings"
	"testing"
)

func TestArchitectureImportsRejectCgo(t *testing.T) {
	t.Parallel()

	findings, err := architectureImportFindings(
		[]string{"tools/sourcepolicy/cgo.go"},
		func(string) ([]byte, error) {
			return []byte("package main\n/* #include \"../actionpolicy/cross_owner.h\" */\nimport \"C\"\n"), nil
		},
	)
	if err != nil {
		t.Fatalf("architectureImportFindings() error = %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "Cgo is not declared") {
		t.Fatalf("architectureImportFindings() = %v, want Cgo finding", findings)
	}
}

func TestArchitectureImportsInspectTestCustody(t *testing.T) {
	t.Parallel()

	imports := []string{
		"celestia.research/assurance/check",
		architectureModule + "/tools/sourcepolicy",
		architectureModule + "/worker/url-reference",
	}
	for _, imported := range imports {
		t.Run(imported, func(t *testing.T) {
			t.Parallel()
			findings, err := architectureImportFindings(
				[]string{"internal/example/example_test.go"},
				func(string) ([]byte, error) {
					return fmt.Appendf(nil, "package example\nimport _ %q\n", imported), nil
				},
			)
			if err != nil || len(findings) != 1 {
				t.Fatalf("architectureImportFindings() = %v, %v", findings, err)
			}
		})
	}
}

func TestArchitectureImportsRejectTestDirectionBypass(t *testing.T) {
	t.Parallel()

	readFile := func(string) ([]byte, error) {
		return []byte("package example\nimport _ \"celestia.research/celestia/internal/operation/urlreference\"\n"), nil
	}
	findings, err := architectureImportFindings(
		[]string{"internal/execution/supervision/rogue_test.go"}, readFile,
	)
	if err != nil || len(findings) != 1 {
		t.Fatalf("architectureImportFindings() = %v, %v", findings, err)
	}
	findings, err = architectureImportFindings(
		[]string{supervisionQualificationTest}, readFile,
	)
	if err != nil || len(findings) != 1 {
		t.Fatalf("qualification test bypass accepted: %v, %v", findings, err)
	}
	readFile = func(string) ([]byte, error) {
		return []byte("package example\nimport _ \"celestia.research/celestia/internal/operation/urlreference/admission\"\n"), nil
	}
	findings, err = architectureImportFindings(
		[]string{supervisionQualificationTest}, readFile,
	)
	if err != nil || len(findings) != 0 {
		t.Fatalf("qualification test dependency rejected: %v, %v", findings, err)
	}
	readFile = func(string) ([]byte, error) {
		return []byte("package example\nimport _ \"" + architectureModule + "/internal/testcargo\"\n"), nil
	}
	findings, err = architectureImportFindings(
		[]string{supervisionQualificationTest}, readFile,
	)
	if err != nil || len(findings) != 0 {
		t.Fatalf("qualification test Cargo owner rejected: %v, %v", findings, err)
	}
}

func TestArchitectureImportsNormaliseMigrationOwners(t *testing.T) {
	t.Parallel()

	reason := forbiddenArchitectureImport(
		"internal/operation/urlreference/transform",
		architectureModule+"/internal/execution/supervision",
	)
	if reason == "" {
		t.Fatal("transformation import of execution accepted")
	}
}

func TestArchitectureImportsAllowAttemptFilesystemOwner(t *testing.T) {
	t.Parallel()

	const attempt = "internal/operation/urlreference/attempt"
	if reason := forbiddenURLReferenceImport(attempt, "internal/linuxamd64feasibility"); reason != "" {
		t.Fatalf("filesystem owner rejected: %s", reason)
	}
	if reason := forbiddenURLReferenceImport(attempt, "internal/linuxamd64feasibility/rogue"); reason == "" {
		t.Fatal("filesystem subpackage accepted")
	}
	if reason := forbiddenURLReferenceImport(attempt, "internal/execution/supervision"); reason == "" {
		t.Fatal("unrelated Production owner accepted")
	}
}

func TestArchitectureImportsRestrictTestCargoOwner(t *testing.T) {
	t.Parallel()

	readFile := func(string) ([]byte, error) {
		return []byte("package example\nimport _ \"" + testCargoImport + "\"\n"), nil
	}
	findings, err := architectureImportFindings(
		[]string{"internal/operation/urlreference/operation_windows.go"}, readFile,
	)
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0], "test Cargo owner") {
		t.Fatalf("runtime test Cargo import accepted: %v, %v", findings, err)
	}
	findings, err = architectureImportFindings([]string{urlOperationTestSupport}, readFile)
	if err != nil || len(findings) != 0 {
		t.Fatalf("declared test Cargo import rejected: %v, %v", findings, err)
	}
}

func TestArchitecturePathsRejectUndeclaredWorkerPackage(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !hasArchitecturePathFinding([]string{"worker/rogue/main.go"}, policy) {
		t.Fatal("undeclared worker Go package accepted")
	}
}
