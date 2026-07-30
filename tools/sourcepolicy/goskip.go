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
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

type buildTarget struct {
	goos   string
	goarch string
}

type goBuildUnit struct {
	target   buildTarget
	patterns []string
}

var policyBuildTargets = []buildTarget{
	{"aix", "ppc64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"dragonfly", "amd64"},
	{"freebsd", "amd64"},
	{"illumos", "amd64"},
	{"js", "wasm"},
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"netbsd", "amd64"},
	{"openbsd", "amd64"},
	{"plan9", "amd64"},
	{"solaris", "amd64"},
	{"wasip1", "wasm"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

func goPackageSkipFindings(
	paths []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	directories, err := goCandidateDirectories(paths, readFile)
	if err != nil || len(directories) == 0 {
		return nil, err
	}
	units, err := goBuildUnits(paths, directories)
	if err != nil {
		return nil, err
	}
	return runGoBuildUnits(units)
}

func goSkipFindings(path string, source []byte) []string {
	if !strings.HasSuffix(path, "_test.go") {
		return nil
	}
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, source, 0)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Go test: %v", path, err)}
	}
	return goSkipFindingsInPackage(files, []*ast.File{file}, map[*ast.File]string{
		file: path,
	})
}

func goSkipFindingsInPackage(
	files *token.FileSet,
	packageFiles []*ast.File,
	names map[*ast.File]string,
) []string {
	info := goTypeInfo(packageFiles, files)
	var findings []string
	for _, file := range packageFiles {
		path := names[file]
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || !isTestingSkip(selector, info) {
				return true
			}
			position := files.Position(selector.Pos())
			findings = append(findings, fmt.Sprintf(
				"%s:%d: Go tests must not skip cases",
				path,
				position.Line,
			))
			return true
		})
	}
	return findings
}

func goTypeInfo(packageFiles []*ast.File, files *token.FileSet) *types.Info {
	info := &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Uses:       make(map[*ast.Ident]types.Object),
	}
	config := types.Config{Importer: importer.Default()}
	if _, checkErr := config.Check(
		packageFiles[0].Name.Name, files, packageFiles, info,
	); checkErr != nil {
		return info
	}
	return info
}

func isTestingSkip(selector *ast.SelectorExpr, info *types.Info) bool {
	if !isSkipMethod(selector.Sel.Name) {
		return false
	}
	if selection := info.Selections[selector]; selection != nil {
		return testingMethod(selection.Obj()) ||
			interfaceTestingSkip(selection)
	}
	return testingMethod(info.Uses[selector.Sel])
}

func interfaceTestingSkip(selection *types.Selection) bool {
	if _, ok := selection.Recv().Underlying().(*types.Interface); !ok {
		return false
	}
	function, ok := selection.Obj().(*types.Func)
	if !ok {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Results().Len() != 0 {
		return false
	}
	switch function.Name() {
	case "Skip":
		return anyVariadicSignature(signature, 0)
	case "Skipf":
		return signature.Params().Len() == 2 &&
			types.Identical(
				signature.Params().At(0).Type(),
				types.Typ[types.String],
			) &&
			anyVariadicSignature(signature, 1)
	case "SkipNow":
		return !signature.Variadic() && signature.Params().Len() == 0
	default:
		return false
	}
}

func anyVariadicSignature(signature *types.Signature, index int) bool {
	if !signature.Variadic() || signature.Params().Len() != index+1 {
		return false
	}
	slice, ok := signature.Params().At(index).Type().(*types.Slice)
	return ok && types.Identical(
		types.Unalias(slice.Elem()),
		types.Unalias(types.Universe.Lookup("any").Type()),
	)
}

func isSkipMethod(name string) bool {
	return name == "Skip" || name == "Skipf" || name == "SkipNow"
}

func testingMethod(object types.Object) bool {
	function, ok := object.(*types.Func)
	return ok && function.Pkg() != nil && function.Pkg().Path() == "testing"
}

func goCandidateDirectories(
	paths []string,
	readFile func(string) ([]byte, error),
) (map[string]bool, error) {
	testDirectories := make(map[string]bool)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			testDirectories[filepath.Dir(path)] = true
		}
	}
	directories := make(map[string]bool)
	for _, path := range paths {
		if filepath.Ext(path) != ".go" ||
			!testDirectories[filepath.Dir(path)] {
			continue
		}
		source, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		candidate, err := hasGoSkipSelector(path, source)
		if err != nil {
			return nil, err
		}
		if candidate {
			directories[filepath.Dir(path)] = true
		}
	}
	return directories, nil
}

func runGoBuildUnits(units []goBuildUnit) ([]string, error) {
	type unitResult struct {
		findings []string
		err      error
	}
	results := make([]unitResult, len(units))
	limit := make(chan struct{}, maxGoBuildLoads)
	var wait sync.WaitGroup
	for index, unit := range units {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			results[index].findings, results[index].err =
				goSkipFindingsForTarget(unit.target, unit.patterns)
		})
	}
	wait.Wait()
	var findings []string
	for _, result := range results {
		if result.err != nil {
			return nil, result.err
		}
		findings = append(findings, result.findings...)
	}
	slices.Sort(findings)
	return slices.Compact(findings), nil
}

func goBuildUnits(
	paths []string,
	directories map[string]bool,
) ([]goBuildUnit, error) {
	var units []goBuildUnit
	for _, target := range policyBuildTargets {
		patterns, err := goBuildSelection(paths, directories, target)
		if err != nil {
			return nil, err
		}
		if len(patterns) == 0 {
			continue
		}
		units = append(units, goBuildUnit{target: target, patterns: patterns})
	}
	return units, nil
}

func goBuildSelection(
	paths []string,
	directories map[string]bool,
	target buildTarget,
) ([]string, error) {
	context := build.Default
	context.GOOS = target.goos
	context.GOARCH = target.goarch
	context.CgoEnabled = false
	selectedDirectories := make(map[string]string)
	for _, path := range paths {
		if filepath.Ext(path) != ".go" || !directories[filepath.Dir(path)] {
			continue
		}
		match, err := context.MatchFile(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf(
				"%s: match Go build constraints: %w", path, err,
			)
		}
		if !match {
			continue
		}
		if strings.HasSuffix(path, "_test.go") {
			selectedDirectories[filepath.Dir(path)] = path
		}
	}
	patterns := make([]string, 0, len(selectedDirectories))
	for directory, testFile := range selectedDirectories {
		switch {
		case directory == ".":
			patterns = append(patterns, ".")
		case filepath.IsAbs(directory):
			patterns = append(patterns, "file="+filepath.ToSlash(testFile))
		default:
			patterns = append(patterns, "./"+filepath.ToSlash(directory))
		}
	}
	slices.Sort(patterns)
	return patterns, nil
}

func hasGoSkipSelector(path string, source []byte) (bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		return false, fmt.Errorf("%s: parse Go test: %w", path, err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if ok && strings.HasSuffix(path, "_test.go") &&
			function.Name.Name == "TestMain" {
			found = true
			return false
		}
		selector, ok := node.(*ast.SelectorExpr)
		if ok && isSkipMethod(selector.Sel.Name) {
			found = true
			return false
		}
		return !found
	})
	return found, nil
}

func goSkipFindingsForTarget(
	target buildTarget,
	patterns []string,
) ([]string, error) {
	environment := append([]string{}, os.Environ()...)
	environment = append(
		environment,
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
		"CGO_ENABLED=0",
	)
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles |
			packages.NeedCompiledGoFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
		Tests: true,
		Env:   environment,
	}, patterns...)
	if err != nil {
		return nil, fmt.Errorf(
			"load Go tests for %s/%s: %w", target.goos, target.goarch, err,
		)
	}
	var findings []string
	for _, loadedPackage := range loaded {
		if len(loadedPackage.Errors) > 0 {
			return nil, fmt.Errorf(
				"load Go tests for %s/%s: %w",
				target.goos,
				target.goarch,
				loadedPackage.Errors[0],
			)
		}
		for _, file := range loadedPackage.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				function, ok := node.(*ast.FuncDecl)
				if !ok {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok || !isTestingSkip(selector, loadedPackage.TypesInfo) {
						return true
					}
					selectorPosition := loadedPackage.Fset.Position(selector.Pos())
					findings = append(findings, fmt.Sprintf(
						"%s:%d: Go tests must not skip cases",
						filepath.ToSlash(selectorPosition.Filename),
						selectorPosition.Line,
					))
					return true
				}
				position := loadedPackage.Fset.Position(function.Pos())
				if strings.HasSuffix(position.Filename, "_test.go") &&
					function.Name.Name == "TestMain" &&
					isTestingMain(function, loadedPackage.TypesInfo) {
					if validTestMain(function, loadedPackage.TypesInfo) {
						return false
					}
					findings = append(findings, fmt.Sprintf(
						"%s:%d: TestMain must terminate with testing.M.Run",
						filepath.ToSlash(position.Filename),
						position.Line,
					))
					return false
				}
				return true
			})
		}
	}
	return findings, nil
}

func validTestMain(function *ast.FuncDecl, info *types.Info) bool {
	if function.Body == nil || len(function.Body.List) == 0 {
		return false
	}
	expression, ok := function.Body.List[len(function.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return false
	}
	exitCall, ok := expression.X.(*ast.CallExpr)
	if !ok || !isOSExit(exitCall, info) {
		return false
	}
	return isTestingRun(exitCall.Args[0], info)
}

func isTestingMain(function *ast.FuncDecl, info *types.Info) bool {
	object, ok := info.Defs[function.Name].(*types.Func)
	if !ok {
		return false
	}
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Params().Len() != 1 || signature.Results().Len() != 0 {
		return false
	}
	pointer, ok := signature.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "testing" &&
		named.Obj().Name() == "M"
}

func isOSExit(call *ast.CallExpr, info *types.Info) bool {
	if len(call.Args) != 1 {
		return false
	}
	exit, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || exit.Sel.Name != "Exit" {
		return false
	}
	exitObject, ok := info.Uses[exit.Sel].(*types.Func)
	return ok && exitObject.Pkg() != nil && exitObject.Pkg().Path() == "os"
}

func isTestingRun(expression ast.Expr, info *types.Info) bool {
	runCall, ok := expression.(*ast.CallExpr)
	if !ok || len(runCall.Args) != 0 {
		return false
	}
	run, ok := runCall.Fun.(*ast.SelectorExpr)
	return ok && run.Sel.Name == "Run" && testingMethod(info.Uses[run.Sel])
}
