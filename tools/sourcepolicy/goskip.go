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

type cgoPolicyImporter struct {
	standard types.Importer
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
	if err := rejectGoIgnoredTests(paths); err != nil {
		return nil, err
	}
	directories, overlay, err := goCandidateDirectories(paths, readFile)
	if err != nil || len(directories) == 0 {
		return nil, err
	}
	if err := rejectUngovernedGoTests(paths, targets, overlay); err != nil {
		return nil, err
	}
	units, err := goBuildUnits(paths, directories, targets, overlay)
	if err != nil {
		return nil, err
	}
	findings := goSourceFallbackFindings(paths, overlay)
	loadedFindings, err := runGoBuildUnits(units)
	if err != nil {
		return nil, err
	}
	findings = append(findings, loadedFindings...)
	slices.Sort(findings)
	return slices.Compact(findings), nil
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
	info, _ := goTypePackage(packageFiles, files)
	return info
}

func goTypePackage(
	packageFiles []*ast.File,
	files *token.FileSet,
) (*types.Info, *types.Package) {
	info := newGoTypeInfo()
	config := types.Config{
		Error: func(error) {},
		Importer: cgoPolicyImporter{
			standard: importer.Default(),
		},
	}
	typed, checkErr := config.Check(
		packageFiles[0].Name.Name, files, packageFiles, info,
	)
	_ = checkErr
	return info, typed
}

func (value cgoPolicyImporter) Import(path string) (*types.Package, error) {
	if path == "C" {
		return types.NewPackage("C", "C"), nil
	}
	return value.standard.Import(path)
}

func newGoTypeInfo() *types.Info {
	return &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
	}
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
	if err := rejectExternalModuleReplacements(paths, readFile); err != nil {
		return nil, nil, err
	}
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
		if err := addGoCandidate(
			path, testDirectories, overlay, readFile,
		); err != nil {
			return nil, nil, err
		}
	}
	return directories, overlay, nil
}

func addGoCandidate(
	path string,
	testDirectories map[string]bool,
	overlay map[string][]byte,
	readFile func(string) ([]byte, error),
) error {
	directory := filepath.Dir(path)
	if isGoNativeSource(path) {
		return rejectTestedNative(path, testDirectories[directory])
	}
	absolute, source, selected, err := snapshotGoSource(path, readFile)
	if err != nil || !selected {
		return err
	}
	overlay[absolute] = slices.Clone(source)
	if err := rejectTestedCGO(path, testDirectories[directory], overlay); err != nil {
		return err
	}
	if !testDirectories[directory] {
		return nil
	}
	_, err = hasGoPolicySelector(path, source)
	return err
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

func snapshotGoSource(
	path string,
	readFile func(string) ([]byte, error),
) (string, []byte, bool, error) {
	if filepath.Ext(path) != ".go" {
		return "", nil, false, nil
	}
	source, err := readFile(path)
	if err != nil {
		return "", nil, false, fmt.Errorf("%s: %w", path, err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, false, fmt.Errorf(
			"%s: resolve Go source: %w",
			path,
			err,
		)
	}
	if err := rejectUnsupportedBuildTags(path, source); err != nil {
		return "", nil, false, err
	}
	return absolute, source, true, nil
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
			if err := ctx.Err(); err != nil {
				results[index].err = err
				return
			}
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				results[index].err = ctx.Err()
				return
			}
			defer func() { <-limit }()
			if err := ctx.Err(); err != nil {
				results[index].err = err
				return
			}
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
	selectedDirectories, cgoDirectories, err := selectGoDirectories(
		paths, directories, context, overlay,
	)
	if err != nil {
		return nil, err
	}
	patterns := make([]string, 0, len(selectedDirectories))
	for directory, testFile := range selectedDirectories {
		if !target.cgo && cgoDirectories[directory] {
			continue
		}
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

func selectGoDirectories(
	paths []string,
	directories map[string]bool,
	context build.Context,
	overlay map[string][]byte,
) (map[string]string, map[string]bool, error) {
	cgoDirectories := make(map[string]bool)
	selectedDirectories := make(map[string]string)
	for _, path := range paths {
		if filepath.Ext(path) != ".go" || !directories[filepath.Dir(path)] {
			continue
		}
		match, err := context.MatchFile(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return nil, nil, fmt.Errorf(
				"%s: match Go build constraints: %w", path, err,
			)
		}
		if !match {
			continue
		}
		importsC, err := goSourceImportsC(path, overlay)
		if err != nil {
			return nil, nil, err
		}
		if importsC {
			cgoDirectories[filepath.Dir(path)] = true
		}
		if strings.HasSuffix(path, "_test.go") {
			selectedDirectories[filepath.Dir(path)] = path
		}
	}
	return selectedDirectories, cgoDirectories, nil
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
		return false, fmt.Errorf("%s: parse Go imports: %w", path, err)
	}
	return goFileImportsC(file), nil
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
	environment := goPolicyEnvironment(target)
	cgo := "0"
	if target.cgo {
		cgo = "1"
	}
	environment = append(
		environment,
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
		"CGO_ENABLED="+cgo,
		"GOPACKAGESDRIVER=off",
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
		inspector := goPolicyInspector{
			loaded:  loadedPackage,
			sources: inventoriedGoSources(overlay),
		}
		findings = append(findings, inspector.findings()...)
	}
	return findings, nil
}

func inventoriedGoSources(overlay map[string][]byte) map[string]bool {
	sources := make(map[string]bool, len(overlay))
	for path := range overlay {
		sources[filepath.Clean(path)] = true
	}
	return sources
}

func goPolicyEnvironment(target buildTarget) []string {
	blocked := map[string]bool{
		"CGO_ENABLED":      true,
		"GOARCH":           true,
		"GOARM64":          true,
		"GOAMD64":          true,
		"GOENV":            true,
		"GOFLAGS":          true,
		"GOOS":             true,
		"GOTOOLCHAIN":      true,
		"GOWORK":           true,
		"GOPACKAGESDRIVER": true,
	}
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		reject := false
		for variable := range blocked {
			if strings.EqualFold(name, variable) {
				reject = true
				break
			}
		}
		if !reject {
			environment = append(environment, entry)
		}
	}
	switch target.goarch {
	case "amd64":
		environment = append(environment, "GOAMD64=v1")
	case "arm64":
		environment = append(environment, "GOARM64=v8.0")
	}
	environment = append(
		environment,
		"GOENV=off",
		"GOFLAGS=",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
	)
	return environment
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
