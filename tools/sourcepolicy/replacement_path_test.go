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
	"path/filepath"
	"testing"
)

func TestSplitPath(t *testing.T) {
	path := filepath.Join("one", "two", "three")
	parts := splitPath(path)
	if len(parts) != 3 ||
		parts[0] != "one" ||
		parts[1] != "two" ||
		parts[2] != "three" {
		t.Fatalf("splitPath(%q) = %v", path, parts)
	}
}
