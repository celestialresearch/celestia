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
	"reflect"
	"strings"
	"testing"
)

func TestExecutableInventory(t *testing.T) {
	t.Parallel()

	input := "100755 abc 0\ttools/run\x00" +
		"100644 def 0\ttools/data\x00"
	files, err := readExecutableInventory(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"tools/run"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("executables = %v, want %v", files, want)
	}
}

func TestExecutableInventoryRejectsMalformed(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"100755 abc 0 tools/run\x00",
		"100755 abc\ttools/run\x00",
		"100755 abc 0\ttools/run",
	} {
		if _, err := readExecutableInventory(strings.NewReader(input)); err == nil {
			t.Fatalf("readExecutableInventory(%q) succeeded", input)
		}
	}
}

func TestScriptOwnershipSignals(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		file       string
		executable bool
		declared   bool
		want       bool
	}{
		"declared":              {file: "tools/run.py", declared: true},
		"extensionless":         {file: "tools/run", executable: true, want: true},
		"ordinary data":         {file: "tools/data.json"},
		"Python":                {file: "tools/run.py", want: true},
		"Windows batch":         {file: "tools/run.bat", want: true},
		"non-executable binary": {file: "tools/data.bin"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			declared := map[string]struct{}{}
			if test.declared {
				declared[test.file] = struct{}{}
			}
			findings := architectureScriptPathFindings(
				test.file, test.executable, declared,
			)
			if got := len(findings) != 0; got != test.want {
				t.Fatalf("findings = %v, want rejection %t", findings, test.want)
			}
		})
	}
}
