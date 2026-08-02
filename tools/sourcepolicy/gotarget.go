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
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type buildTarget struct {
	goos   string
	goarch string
	cgo    bool
	race   bool
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

func goCandidateDirectories(
	paths []string,
	readFile func(string) ([]byte, error),
) (map[string]bool, map[string][]byte, error) {
	if err := rejectModuleReplacements(paths, readFile); err != nil {
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
		return false, fmt.Errorf("%s: parse Go test: %w", path, quotedDiagnostic(err))
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
