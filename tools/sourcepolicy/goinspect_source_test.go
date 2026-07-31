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
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestGoInspectorLimitsDirectivesToSources(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "fixture_test.go")
	generatedPath := filepath.Join(root, "_cgo_generated.go")
	files := token.NewFileSet()
	testFile := parsePolicySource(t, files, testPath, `package fixture
func exerciseGenerated(value generatedSkipper) { value.Skip() }
`)
	generatedFile := parsePolicySource(t, files, generatedPath, `package fixture
//go:linkname generatedRuntime runtime.generatedRuntime
type generatedSkipper interface { Skip(...any) }
`)
	info := &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
	}
	typed, err := (&types.Config{}).Check(
		"fixture.invalid/generated",
		files,
		[]*ast.File{testFile, generatedFile},
		info,
	)
	if err != nil {
		t.Fatal(err)
	}
	loaded := &packages.Package{
		Name:      "fixture",
		PkgPath:   typed.Path(),
		Fset:      files,
		Syntax:    []*ast.File{testFile, generatedFile},
		Types:     typed,
		TypesInfo: info,
	}
	inspector := goPolicyInspector{
		loaded:  loaded,
		sources: map[string]bool{filepath.Clean(testPath): true},
	}
	findings := inspector.findings()
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want typed Skip rejection only", findings)
	}
	if strings.Contains(findings[0], "go:linkname") {
		t.Fatalf("generated directive was reported: %v", findings)
	}
}

func parsePolicySource(
	t *testing.T,
	files *token.FileSet,
	path, source string,
) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(files, path, source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
