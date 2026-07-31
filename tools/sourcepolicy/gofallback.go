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
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/tools/go/packages"
)

func policyTargets() []buildTarget {
	targets := make([]buildTarget, 0, len(policyBuildTargets)*3)
	for _, target := range policyBuildTargets {
		targets = append(targets, target)
		if target.goos == runtime.GOOS &&
			target.goarch == runtime.GOARCH &&
			build.Default.CgoEnabled {
			cgoTarget := target
			cgoTarget.cgo = true
			targets = append(targets, cgoTarget)
		}
		if policyRaceTargets[target.goos+"/"+target.goarch] {
			raceTarget := target
			raceTarget.race = true
			targets = append(targets, raceTarget)
		}
	}
	return targets
}

func goSourceFallbackFindings(
	paths []string,
	overlay map[string][]byte,
) []string {
	testDirectories := make(map[string]bool)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			testDirectories[filepath.Dir(path)] = true
		}
	}
	directories := make(map[string][]string)
	for _, path := range paths {
		if filepath.Ext(path) == ".go" &&
			testDirectories[filepath.Dir(path)] {
			directories[filepath.Dir(path)] = append(
				directories[filepath.Dir(path)],
				path,
			)
		}
	}
	var findings []string
	for _, directoryPaths := range directories {
		findings = append(
			findings,
			goFallbackDirectoryFindings(directoryPaths, overlay)...,
		)
	}
	return findings
}

func rejectUngovernedGoTests(
	paths []string,
	targets []buildTarget,
	overlay map[string][]byte,
) error {
	for _, path := range paths {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		selected, err := goTestSelected(path, targets, overlay)
		if err != nil {
			return err
		}
		if !selected {
			return fmt.Errorf("%s: Go test is outside the governed target matrix", path)
		}
	}
	return nil
}

func rejectGoIgnoredTests(paths []string) error {
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") && goIgnoredTestPath(path) {
			return fmt.Errorf("%s: Go test is outside the governed package inventory", path)
		}
	}
	return nil
}

func goTestSelected(
	path string,
	targets []buildTarget,
	overlay map[string][]byte,
) (bool, error) {
	for _, target := range targets {
		context := policyBuildContext(target, overlay)
		matched, err := context.MatchFile(
			filepath.Dir(path), filepath.Base(path),
		)
		if err != nil {
			return false, fmt.Errorf(
				"%s: match Go build constraints: %w", path, err,
			)
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func goIgnoredTestPath(path string) bool {
	relative, inside, err := repositoryRelativePath(path)
	if err != nil {
		return true
	}
	if !inside {
		return false
	}
	for part := range strings.SplitSeq(relative, string(filepath.Separator)) {
		if part == "." || part == ".." {
			continue
		}
		if part == "testdata" || part == "vendor" ||
			strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			return true
		}
	}
	return false
}

func repositoryRelativePath(path string) (string, bool, error) {
	repositoryRoot, err := filepath.Abs(".")
	if err != nil {
		return "", false, err
	}
	absolute := filepath.Clean(path)
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(repositoryRoot, absolute)
	} else if !strings.EqualFold(
		filepath.VolumeName(repositoryRoot), filepath.VolumeName(absolute),
	) {
		return "", false, nil
	}
	relative, err := filepath.Rel(repositoryRoot, absolute)
	if err != nil {
		return "", false, err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false, nil
	}
	return relative, true, nil
}

func goFallbackDirectoryFindings(
	paths []string,
	overlay map[string][]byte,
) []string {
	files := token.NewFileSet()
	syntaxByPackage := make(map[string][]*ast.File)
	sources := make(map[string]bool)
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		source, found := overlay[absolute]
		if !found {
			continue
		}
		file, err := parser.ParseFile(
			files, absolute, source, parser.ParseComments,
		)
		if err != nil {
			continue
		}
		syntaxByPackage[file.Name.Name] = append(
			syntaxByPackage[file.Name.Name],
			file,
		)
		sources[filepath.Clean(absolute)] = true
	}
	var findings []string
	for name, syntax := range syntaxByPackage {
		findings = append(
			findings,
			goFallbackPackageFindings(name, files, syntax, sources)...,
		)
	}
	return findings
}

func goFallbackPackageFindings(
	name string,
	files *token.FileSet,
	syntax []*ast.File,
	sources map[string]bool,
) []string {
	info, typed := goTypePackage(syntax, files)
	loaded := &packages.Package{
		Name:      name,
		Fset:      files,
		Syntax:    syntax,
		Types:     typed,
		TypesInfo: info,
	}
	inspector := goPolicyInspector{loaded: loaded, sources: sources}
	return inspector.findings()
}

func goFileImportsC(file *ast.File) bool {
	for _, imported := range file.Imports {
		if imported.Path.Value == `"C"` {
			return true
		}
	}
	return false
}
