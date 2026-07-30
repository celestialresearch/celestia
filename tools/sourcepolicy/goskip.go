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
	"context"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

type buildTarget struct {
	goos   string
	goarch string
	cgo    bool
}

type goBuildUnit struct {
	target   buildTarget
	patterns []string
}

var policyBuildTargets = []buildTarget{
	{goos: "aix", goarch: "ppc64"},
	{goos: "darwin", goarch: "amd64"},
	{goos: "darwin", goarch: "arm64"},
	{goos: "dragonfly", goarch: "amd64"},
	{goos: "freebsd", goarch: "amd64"},
	{goos: "illumos", goarch: "amd64"},
	{goos: "js", goarch: "wasm"},
	{goos: "linux", goarch: "amd64"},
	{goos: "linux", goarch: "arm64"},
	{goos: "netbsd", goarch: "amd64"},
	{goos: "openbsd", goarch: "amd64"},
	{goos: "plan9", goarch: "amd64"},
	{goos: "solaris", goarch: "amd64"},
	{goos: "wasip1", goarch: "wasm"},
	{goos: "windows", goarch: "amd64"},
	{goos: "windows", goarch: "arm64"},
}

func goPackageSkipFindings(
	paths []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	return goPackageSkipFindingsWithTargets(
		paths,
		readFile,
		policyTargets(),
	)
}

func goPackageSkipFindingsWithTargets(
	paths []string,
	readFile func(string) ([]byte, error),
	targets []buildTarget,
) ([]string, error) {
	directories, err := goCandidateDirectories(paths, readFile)
	if err != nil || len(directories) == 0 {
		return nil, err
	}
	units, err := goBuildUnits(paths, directories, targets)
	if err != nil {
		return nil, err
	}
	return runGoBuildUnits(units)
}

func policyTargets() []buildTarget {
	targets := slices.Clone(policyBuildTargets)
	if build.Default.CgoEnabled {
		targets = append(targets, buildTarget{
			goos: runtime.GOOS, goarch: runtime.GOARCH, cgo: true,
		})
	}
	return targets
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
		candidate, err := hasGoPolicySelector(path, source)
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
	ctx, cancel := context.WithTimeout(
		context.Background(),
		maxGoPolicyDuration,
	)
	defer cancel()
	return runGoBuildUnitsWith(ctx, units, packages.Load)
}

func runGoBuildUnitsWith(
	ctx context.Context,
	units []goBuildUnit,
	load packageLoader,
) ([]string, error) {
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
				goSkipFindingsForTargetWith(
					ctx,
					unit.target,
					unit.patterns,
					load,
				)
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
	targets []buildTarget,
) ([]goBuildUnit, error) {
	var units []goBuildUnit
	for _, target := range targets {
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
	context.CgoEnabled = target.cgo
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

func hasGoPolicySelector(path string, source []byte) (bool, error) {
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
		if ok && (isSkipMethod(selector.Sel.Name) || selector.Sel.Name == "Exit") {
			found = true
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if ok && identifier.Name == "Exit" {
			found = true
			return false
		}
		return !found
	})
	return found, nil
}

type packageLoader func(
	*packages.Config,
	...string,
) ([]*packages.Package, error)

func goSkipFindingsForTargetWith(
	ctx context.Context,
	target buildTarget,
	patterns []string,
	load packageLoader,
) ([]string, error) {
	environment := append([]string{}, os.Environ()...)
	cgo := "0"
	if target.cgo {
		cgo = "1"
	}
	environment = append(
		environment,
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
		"CGO_ENABLED="+cgo,
	)
	loaded, err := load(&packages.Config{
		Context: ctx,
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
		if loadedPackage.Name == "main" &&
			strings.HasSuffix(loadedPackage.PkgPath, ".test") {
			continue
		}
		inspector := goPolicyInspector{loaded: loadedPackage}
		findings = append(findings, inspector.findings()...)
	}
	return findings, nil
}

type goPolicyInspector struct {
	loaded *packages.Package
	found  []string
}

func (inspector *goPolicyInspector) findings() []string {
	for _, file := range inspector.loaded.Syntax {
		ast.Inspect(file, inspector.inspect)
	}
	return inspector.found
}

func (inspector *goPolicyInspector) inspect(node ast.Node) bool {
	switch value := node.(type) {
	case *ast.FuncDecl:
		return inspector.inspectFunction(value)
	case *ast.SelectorExpr:
		return inspector.inspectSelector(value)
	case *ast.Ident:
		return inspector.inspectIdentifier(value)
	case *ast.CallExpr:
		return inspector.inspectCall(value)
	default:
		return true
	}
}

func (inspector *goPolicyInspector) inspectFunction(function *ast.FuncDecl) bool {
	position := inspector.loaded.Fset.Position(function.Pos())
	if inspector.loaded.Name == "main" &&
		function.Name.Name == "main" &&
		!strings.HasSuffix(position.Filename, "_test.go") {
		return false
	}
	if !strings.HasSuffix(position.Filename, "_test.go") ||
		function.Name.Name != "TestMain" ||
		!isTestingMain(function, inspector.loaded.TypesInfo) {
		return true
	}
	if !validTestMainSyntax(function, inspector.loaded.TypesInfo) {
		inspector.add(function, "TestMain violates the local execution syntax")
	}
	return false
}

func (inspector *goPolicyInspector) inspectSelector(selector *ast.SelectorExpr) bool {
	if isTestingSkip(selector, inspector.loaded.TypesInfo) {
		inspector.add(selector, "Go tests must not skip cases")
		return true
	}
	if isProcessExitFunction(selector, inspector.loaded.TypesInfo) {
		inspector.add(selector, "Go tests must not alias process exit")
		return false
	}
	return true
}

func (inspector *goPolicyInspector) inspectIdentifier(identifier *ast.Ident) bool {
	if !isProcessExitFunction(identifier, inspector.loaded.TypesInfo) {
		return true
	}
	inspector.add(identifier, "Go tests must not alias process exit")
	return false
}

func (inspector *goPolicyInspector) inspectCall(call *ast.CallExpr) bool {
	if inspector.isExecutableMainCall(call) {
		inspector.add(call, "Go tests must not invoke executable main")
		return false
	}
	if !isProcessExit(call, inspector.loaded.TypesInfo) {
		return true
	}
	if !nonzeroExitCode(call.Args[0]) {
		inspector.add(call, "Go tests must not exit successfully")
	}
	return false
}

func (inspector *goPolicyInspector) isExecutableMainCall(call *ast.CallExpr) bool {
	position := inspector.loaded.Fset.Position(call.Pos())
	if inspector.loaded.Name != "main" ||
		!strings.HasSuffix(position.Filename, "_test.go") {
		return false
	}
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || identifier.Name != "main" {
		return false
	}
	function, ok := inspector.loaded.TypesInfo.Uses[identifier].(*types.Func)
	return ok && function.Pkg() == inspector.loaded.Types
}

func (inspector *goPolicyInspector) add(node ast.Node, message string) {
	position := inspector.loaded.Fset.Position(node.Pos())
	inspector.found = append(inspector.found, fmt.Sprintf(
		"%s:%d: %s",
		filepath.ToSlash(position.Filename),
		position.Line,
		message,
	))
}

func validTestMainSyntax(function *ast.FuncDecl, info *types.Info) bool {
	if function.Body == nil || len(function.Body.List) == 0 ||
		testMainSyntaxBypass(function.Body.List[:len(function.Body.List)-1], info) {
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

func testMainSyntaxBypass(statements []ast.Stmt, info *types.Info) bool {
	bypass := false
	for _, statement := range statements {
		ast.Inspect(statement, func(node ast.Node) bool {
			if bypass {
				return false
			}
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
			if _, ok := node.(*ast.ReturnStmt); ok {
				bypass = true
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !isOSExit(call, info) {
				return true
			}
			if !nonzeroExitCode(call.Args[0]) {
				bypass = true
			}
			return true
		})
	}
	return bypass
}

func nonzeroExitCode(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return false
	}
	value, err := strconv.ParseInt(literal.Value, 0, 64)
	return err == nil && value != 0
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
	return isOSExitFunction(call.Fun, info)
}

func isProcessExit(call *ast.CallExpr, info *types.Info) bool {
	if len(call.Args) != 1 {
		return false
	}
	return isProcessExitFunction(call.Fun, info)
}

func isProcessExitFunction(expression ast.Expr, info *types.Info) bool {
	if isOSExitFunction(expression, info) {
		return true
	}
	object := functionObject(expression, "Exit", info)
	return object != nil && object.Pkg() != nil &&
		object.Pkg().Path() == "syscall"
}

func isOSExitFunction(expression ast.Expr, info *types.Info) bool {
	object := functionObject(expression, "Exit", info)
	return object != nil && object.Pkg() != nil && object.Pkg().Path() == "os"
}

func functionObject(
	expression ast.Expr,
	name string,
	info *types.Info,
) *types.Func {
	var object types.Object
	switch exit := expression.(type) {
	case *ast.SelectorExpr:
		if exit.Sel.Name != name {
			return nil
		}
		object = info.Uses[exit.Sel]
	case *ast.Ident:
		if exit.Name != name {
			return nil
		}
		object = info.Uses[exit]
	default:
		return nil
	}
	function, ok := object.(*types.Func)
	if !ok {
		return nil
	}
	return function
}

func isTestingRun(expression ast.Expr, info *types.Info) bool {
	runCall, ok := expression.(*ast.CallExpr)
	if !ok || len(runCall.Args) != 0 {
		return false
	}
	run, ok := runCall.Fun.(*ast.SelectorExpr)
	return ok && run.Sel.Name == "Run" && testingMethod(info.Uses[run.Sel])
}
