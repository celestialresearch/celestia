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

func TestCargoConfigurationShapes(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		findings int
	}{
		{"empty", "", 0},
		{"benign scalar", "net = true", 0},
		{"boolean flags", "[build]\nrustflags = true", 1},
		{"mixed flags", "[build]\nrustflags = [\"-C\", 1]", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := cargoConfigFindings(".cargo/config.toml", []byte(test.source))
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}
