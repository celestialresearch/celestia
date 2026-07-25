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

//go:build windows

package attemptstore

import "testing"

func TestPublishFileRejectsInvalidPaths(t *testing.T) {
	if err := publishFile("invalid\x00source", "target", t.TempDir()); err == nil {
		t.Fatal("invalid source path accepted")
	}
	if err := publishFile("source", "invalid\x00target", t.TempDir()); err == nil {
		t.Fatal("invalid target path accepted")
	}
}
