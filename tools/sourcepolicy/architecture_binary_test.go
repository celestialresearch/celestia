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

func TestArchitectureRejectsWindowsBinaries(t *testing.T) {
	t.Parallel()

	files := []string{"tools/sourcepolicy/rogue.exe"}
	findings, err := architectureWindowsBinaryFindings(files, func(string) ([]byte, error) {
		return append([]byte{'M', 'Z'}, make([]byte, 1022)...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "PE executable") {
		t.Fatalf("findings = %v, want PE executable finding", findings)
	}
}

func TestArchitectureWindowsBinaryReadFailure(t *testing.T) {
	t.Parallel()

	want := fmt.Errorf("read failed")
	_, err := architectureWindowsBinaryFindings(
		[]string{"tools/sourcepolicy/rogue.exe"},
		func(string) ([]byte, error) { return nil, want },
	)
	if err != want {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
