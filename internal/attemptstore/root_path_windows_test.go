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

import (
	"path/filepath"
	"testing"
)

func TestEvidenceRootPathPolicy(t *testing.T) {
	tests := map[string]struct {
		path string
		want bool
	}{
		"local":    {path: filepath.Join(t.TempDir(), "evidence"), want: true},
		"relative": {path: "evidence"},
		"UNC":      {path: `\\invalid.example\share\evidence`},
		"device":   {path: `\\?\C:\evidence`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := validEvidenceRootPath(test.path); actual != test.want {
				t.Fatalf("validEvidenceRootPath(%q) = %t, want %t", test.path, actual, test.want)
			}
		})
	}
}
