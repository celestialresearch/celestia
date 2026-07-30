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
		if ok && function.Name.Name == "TestMain" {
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
				if ok && function.Name.Name == "TestMain" {
					if validTestMain(function, loadedPackage.TypesInfo) {
						return false
					}
					position := loadedPackage.Fset.Position(function.Pos())
					findings = append(findings, fmt.Sprintf(
						"%s:%d: TestMain must terminate with testing.M.Run",
						filepath.ToSlash(position.Filename),
						position.Line,
					))
					return false
				}
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
