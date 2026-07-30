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

//go:build !windows

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRejectsUnsupportedPlatform(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence")
	if _, err := New(path); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported platform result: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported store accessed evidence path: %v", err)
	}
}
