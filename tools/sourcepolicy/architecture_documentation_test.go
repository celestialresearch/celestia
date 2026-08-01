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

import "testing"

func TestFinalPackageRequiresDocFile(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	policy.Packages = []string{"tools/example"}
	read := func(string) ([]byte, error) {
		return []byte("// Package example owns the fixture.\npackage example\n"), nil
	}
	findings, err := packageDocumentationFindings(
		[]string{"tools/example/main.go"}, policy, read,
	)
	if err != nil || len(findings) != 1 {
		t.Fatalf("main.go documentation = %v, %v", findings, err)
	}
	findings, err = packageDocumentationFindings(
		[]string{"tools/example/doc.go"}, policy, read,
	)
	if err != nil || len(findings) != 0 {
		t.Fatalf("doc.go documentation = %v, %v", findings, err)
	}
}
