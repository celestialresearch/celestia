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
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestActionPolicySplitInventoryMatches(t *testing.T) {
	t.Parallel()

	findings, err := actionPolicySplitDeclarationFindings(expectedSplitFiles(), readArchitectureFile)
	if err != nil {
		t.Fatalf("actionPolicySplitDeclarationFindings() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("actionPolicySplitDeclarationFindings() = %v", findings)
	}
}

func TestActionPolicySplitInventoryRejectsDrift(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path string
		edit func([]byte) []byte
		want string
	}{
		"declaration": {
			path: "tools/actionpolicy/actions.go",
			edit: func(source []byte) []byte {
				return append(source, []byte("\nvar actionInventoryProbe = 1\n")...)
			},
			want: "source inventory differs",
		},
		"test target": {
			path: "tools/actionpolicy/actions_test.go",
			edit: func(source []byte) []byte {
				return bytes.Replace(source, []byte("func Test"), []byte("func Check"), 1)
			},
			want: "test target inventory differs",
		},
		"fuzz target": {
			path: "tools/actionpolicy/fuzz_test.go",
			edit: func(source []byte) []byte {
				return bytes.Replace(source, []byte("func Fuzz"), []byte("func Check"), 1)
			},
			want: "test target inventory differs",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			readFile := func(file string) ([]byte, error) {
				source, err := readArchitectureFile(file)
				if err != nil || file != test.path {
					return source, err
				}
				return test.edit(source), nil
			}
			findings, err := actionPolicySplitDeclarationFindings(expectedSplitFiles(), readFile)
			if err != nil {
				t.Fatalf("actionPolicySplitDeclarationFindings() error = %v", err)
			}
			if !slices.ContainsFunc(findings, func(finding string) bool {
				return strings.Contains(finding, test.want)
			}) {
				t.Fatalf("findings = %v, want %q", findings, test.want)
			}
		})
	}
}

func readArchitectureFile(file string) ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
}

func TestArchitectureRejectsUndeclaredActionPolicyTest(t *testing.T) {
	t.Parallel()

	files := append(expectedSplitFiles(), "tools/actionpolicy/rogue_test.go")
	assertSplitFinding(t, files, "undeclared split source")
}
