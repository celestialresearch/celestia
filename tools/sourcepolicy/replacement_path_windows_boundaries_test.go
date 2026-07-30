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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementPathAcceptsOrdinaryDirectories(t *testing.T) {
	root := t.TempDir()
	ordinary := filepath.Join(root, "ordinary")
	if err := os.Mkdir(ordinary, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		root    string
		target  string
		wantErr bool
	}{
		{
			name:   "root itself",
			root:   root,
			target: root,
		},
		{
			name:   "ordinary directory",
			root:   root,
			target: ordinary,
		},
		{
			name:    "missing component",
			root:    root,
			target:  filepath.Join(root, "missing"),
			wantErr: true,
		},
		{
			name:    "invalid UTF-16 component",
			root:    root,
			target:  filepath.Join(root, "invalid\x00component"),
			wantErr: true,
		},
		{
			name:    "different volume",
			root:    `C:\root`,
			target:  `Z:\target`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linked, err := replacementPathLinked(test.root, test.target)
			if test.wantErr {
				if err == nil {
					t.Fatalf("linked = %v, want error", linked)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if linked {
				t.Fatal("ordinary path reported as linked")
			}
		})
	}
}
