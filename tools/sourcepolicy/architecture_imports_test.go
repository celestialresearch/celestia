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
		return []byte("package example\nimport _ \"celestia.research/celestia/internal/urloperation\"\n"), nil
	}
	findings, err := architectureImportFindings(
		[]string{"internal/processsupervision/rogue_test.go"}, readFile,
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
		return []byte("package example\nimport _ \"celestia.research/celestia/internal/urladmission\"\n"), nil
	}
	findings, err = architectureImportFindings(
		[]string{supervisionQualificationTest}, readFile,
	)
	if err != nil || len(findings) != 0 {
		t.Fatalf("qualification test dependency rejected: %v, %v", findings, err)
	}
}

func TestArchitectureImportsNormaliseMigrationOwners(t *testing.T) {
	t.Parallel()

	reason := forbiddenArchitectureImport(
		"internal/urlreferencev1",
		architectureModule+"/internal/processsupervision",
	)
	if reason == "" {
		t.Fatal("migration transformation import of execution accepted")
	}
}

func TestArchitecturePathsRejectUndeclaredWorkerPackage(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !hasArchitecturePathFinding([]string{"worker/rogue/main.go"}, policy) {
		t.Fatal("undeclared worker Go package accepted")
	}
}
