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
	"fmt"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

func rejectModuleReplacements(
	paths []string,
	readFile func(string) ([]byte, error),
) error {
	repositoryRoot, err := filepath.Abs(".")
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	for _, path := range paths {
		if filepath.Base(path) != "go.mod" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("%s: resolve Go module: %w", path, err)
		}
		if filepath.Clean(absolute) != filepath.Join(repositoryRoot, "go.mod") {
			return fmt.Errorf("%s: nested Go modules are unsupported", path)
		}
		source, err := readFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		module, err := modfile.Parse(path, source, nil)
		if err != nil {
			return fmt.Errorf("%s: parse Go module: %w", path, quotedDiagnostic(err))
		}
		if len(module.Replace) != 0 {
			return fmt.Errorf("%s: Go module replacements are prohibited", path)
		}
	}
	return nil
}
