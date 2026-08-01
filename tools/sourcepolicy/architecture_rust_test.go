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
	"strings"
	"testing"
)

func TestArchitectureRustTargets(t *testing.T) {
	t.Chdir("../..")

	read := func(path string) ([]byte, error) {
		if path == "worker/url-reference/Cargo.toml" {
			return []byte(`[package]
name = "celestia-url-reference"

[[bin]]
name = "celestia-url-reference"
path = "../qualification-fixtures/src/bin/hostile.rs"
`), nil
		}
		return readSource(path)
	}
	findings, err := architectureRustTargetFindings(read)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "Rust targets") {
		t.Fatalf("findings = %v", findings)
	}
}
