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

	for name, source := range map[string]string{
		"cross-package path": `[package]
name = "celestia-url-reference"

[[bin]]
name = "celestia-url-reference"
path = "../qualification-fixtures/src/bin/hostile.rs"
		`,
		"disabled implicit target": `[package]
name = "celestia-url-reference"
autobins = false
		`,
		"malformed targets": `bin = "invalid"
[package]
name = "celestia-url-reference"
		`,
		"custom build target": `[package]
name = "celestia-url-reference"
build = "build.rs"
		`,
	} {
		t.Run(name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if path == "worker/url-reference/Cargo.toml" {
					return []byte(source), nil
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
		})
	}
}
