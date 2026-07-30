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

package main

import (
	"os"
	"path/filepath"
)

func replacementPathLinked(root, target string) (bool, error) {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false, err
	}
	current := root
	for _, component := range splitPath(relative) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true, nil
		}
	}
	return false, nil
}
