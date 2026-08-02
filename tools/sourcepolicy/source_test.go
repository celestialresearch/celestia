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
	"testing"
)

func TestReadSourceBoundsRepository(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(parent, "outside.rs"), []byte("outside"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "source.rs"), []byte("inside"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, maxSourceBytes+1)
	if err := os.WriteFile(
		filepath.Join(root, "oversized.rs"), oversized, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	source, err := readSource("source.rs")
	if err != nil || string(source) != "inside" {
		t.Fatalf("readSource(source.rs) = %q, %v", source, err)
	}
	for _, path := range []string{
		"../outside.rs",
		".",
		"oversized.rs",
	} {
		if _, err := readSource(path); err == nil {
			t.Fatalf("readSource(%q) succeeded", path)
		}
	}
}
