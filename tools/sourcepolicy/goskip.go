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
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
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
	cgo    bool
	race   bool
}

type goBuildUnit struct {
	target   buildTarget
	patterns []string
	overlay  map[string][]byte
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

var policyRaceTargets = map[string]bool{
	"darwin/amd64":  true,
	"darwin/arm64":  true,
	"freebsd/amd64": true,
	"linux/amd64":   true,
	"linux/arm64":   true,
	"netbsd/amd64":  true,
	"windows/amd64": true,
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
	directories, overlay, err := goCandidateDirectories(paths, readFile)
	if err != nil || len(directories) == 0 {
		return nil, err
	}
	units, err := goBuildUnits(paths, directories, targets, overlay)
	if err != nil {
		return nil, err
	}
	return runGoBuildUnits(units)
}

func policyTargets() []buildTarget {
	targets := make([]buildTarget, 0, len(policyBuildTargets)*3)
	for _, target := range policyBuildTargets {
		targets = append(targets, target)
		target.cgo = true
		targets = append(targets, target)
		if policyRaceTargets[target.goos+"/"+target.goarch] {
			target.race = true
			targets = append(targets, target)
		}
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
) (map[string]bool, map[string][]byte, error) {
	testDirectories := make(map[string]bool)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			testDirectories[filepath.Dir(path)] = true
		}
	}
	directories := make(map[string]bool, len(testDirectories))
	overlay := make(map[string][]byte)
	for directory := range testDirectories {
		directories[directory] = true
	}
	for _, path := range paths {
		if filepath.Ext(path) != ".go" {
			continue
		}
		source, err := readFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: resolve Go source: %w", path, err)
		}
		overlay[absolute] = slices.Clone(source)
		if !testDirectories[filepath.Dir(path)] {
			continue
		}
		_, err = hasGoPolicySelector(path, source)
		if err != nil {
			return nil, nil, err
		}
	}
	return directories, overlay, nil
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
				goSkipFindingsForTargetWithOverlay(
					ctx,
					unit.target,
					unit.patterns,
					unit.overlay,
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
	overlay map[string][]byte,
) ([]goBuildUnit, error) {
	var units []goBuildUnit
	for _, target := range targets {
		patterns, err := goBuildSelection(paths, directories, target, overlay)
		if err != nil {
			return nil, err
		}
		if len(patterns) == 0 {
			continue
		}
		units = append(units, goBuildUnit{
			target: target, patterns: patterns, overlay: overlay,
		})
	}
	return units, nil
}

func goBuildSelection(
	paths []string,
	directories map[string]bool,
	target buildTarget,
	overlay map[string][]byte,
) ([]string, error) {
	context := policyBuildContext(target, overlay)
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

func policyBuildContext(
	target buildTarget,
	overlay map[string][]byte,
) build.Context {
	context := build.Default
	context.GOOS = target.goos
	context.GOARCH = target.goarch
	context.CgoEnabled = target.cgo
	if target.race {
		context.BuildTags = append(context.BuildTags, "race")
	}
	context.OpenFile = func(path string) (io.ReadCloser, error) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		source, found := overlay[absolute]
		if !found {
			return nil, os.ErrNotExist
		}
		return io.NopCloser(bytes.NewReader(source)), nil
	}
	return context
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
	return goSkipFindingsForTargetWithOverlay(
		ctx, target, patterns, nil, load,
	)
}

func goSkipFindingsForTargetWithOverlay(
	ctx context.Context,
	target buildTarget,
	patterns []string,
	overlay map[string][]byte,
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
	buildFlags := []string(nil)
	if target.race {
		buildFlags = []string{"-tags=race"}
	}
	repositoryRoot, err := filepath.Abs(".")
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	loaded, err := load(&packages.Config{
		Context: ctx,
		Mode: packages.NeedName | packages.NeedFiles |
			packages.NeedCompiledGoFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps |
			packages.NeedModule,
		Tests:      true,
		Env:        environment,
		BuildFlags: buildFlags,
		Overlay:    overlay,
	}, patterns...)
	if err != nil {
		return nil, fmt.Errorf(
			"load Go tests for %s/%s: %w", target.goos, target.goarch, err,
		)
	}
	var findings []string
	for _, loadedPackage := range policyPackages(loaded, repositoryRoot) {
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

func policyPackages(
	roots []*packages.Package,
	repositoryRoot string,
) []*packages.Package {
	queue := slices.Clone(roots)
	seen := make(map[string]bool)
	var result []*packages.Package
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil || seen[current.ID] {
			continue
		}
		seen[current.ID] = true
		result = append(result, current)
		for _, imported := range current.Imports {
			if packageInsideRepository(imported, repositoryRoot) {
				queue = append(queue, imported)
			}
		}
	}
	return result
}

func packageInsideRepository(
	loaded *packages.Package,
	repositoryRoot string,
) bool {
	if loaded == nil {
		return false
	}
	for _, path := range loaded.CompiledGoFiles {
		relative, err := filepath.Rel(repositoryRoot, path)
		if err == nil && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
