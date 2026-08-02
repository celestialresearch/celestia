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
	"os"
	"path/filepath"
	"testing"
)

func writeGoPolicyFixture(
	t *testing.T,
	root string,
	sources map[string]string,
) {
	t.Helper()
	for path, source := range sources {
		path = filepath.FromSlash(path)
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}
