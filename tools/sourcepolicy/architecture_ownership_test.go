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

func TestArchitectureSourceOwnership(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	tests := map[string]struct {
		file string
		want bool
	}{
		"declared internal": {file: "internal/attemptstore/native.c"},
		"declared worker":   {file: "worker/url-reference/data.bin"},
		"command data":      {file: "cmd/rogue/data.json", want: true},
		"native source":     {file: "tools/rogue/main.c", want: true},
		"script data":       {file: ".github/scripts/rogue.txt", want: true},
		"worker data":       {file: "worker/rogue/data.bin", want: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			findings := architecturePathFindings([]string{test.file}, nil, policy)
			if got := len(findings) != 0; got != test.want {
				t.Fatalf("findings = %v, want rejection %t", findings, test.want)
			}
		})
	}
}
