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
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
)

type cgoPolicyImporter struct {
	standard types.Importer
}

func rejectTestedNative(path string, tested bool) error {
	if !tested {
		return nil
	}
	return fmt.Errorf(
		"%s: Go native source is outside the test policy analyser", path,
	)
}

func rejectTestedCGO(path string, tested bool, overlay map[string][]byte) error {
	if !tested {
		return nil
	}
	importsC, err := goSourceImportsC(path, overlay)
	if err != nil {
		return err
	}
	if importsC {
		return fmt.Errorf(
			"%s: cgo is unsupported in packages containing Go tests", path,
		)
	}
	return nil
}

func isGoNativeSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".s", ".c", ".cc", ".cpp", ".cxx", ".m", ".mm",
		".f", ".for", ".f90", ".h", ".hh", ".hpp", ".hxx",
		".swig", ".swigcxx", ".syso":
		return true
	default:
		return false
	}
}

func goSourceImportsC(
	path string,
	overlay map[string][]byte,
) (bool, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("%s: resolve Go source: %w", path, err)
	}
	source, found := overlay[absolute]
	if !found {
		return false, nil
	}
	file, err := parser.ParseFile(
		token.NewFileSet(), path, source, parser.ImportsOnly,
	)
	if err != nil {
		return false, fmt.Errorf("%s: parse Go imports: %w", path, quotedDiagnostic(err))
	}
	return goFileImportsC(file), nil
}
