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
	"testing"
)

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
					return []byte(fmt.Sprintf("package example\nimport _ %q\n", imported)), nil
				},
			)
			if err != nil || len(findings) != 1 {
				t.Fatalf("architectureImportFindings() = %v, %v", findings, err)
			}
		})
	}
}

func TestArchitectureImportsNormaliseLegacyOwners(t *testing.T) {
	t.Parallel()

	reason := forbiddenArchitectureImport(
		"internal/urlreferencev1",
		architectureModule+"/internal/processsupervision",
	)
	if reason == "" {
		t.Fatal("legacy transformation import of execution accepted")
	}
}

func TestArchitecturePathsRejectUndeclaredWorkerPackage(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	if !hasArchitecturePathFinding([]string{"worker/rogue/main.go"}, policy) {
		t.Fatal("undeclared worker Go package accepted")
	}
}
