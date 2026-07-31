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
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"

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
	directories := make(map[string][]string)
	for _, path := range paths {
		if filepath.Ext(path) == ".go" {
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
