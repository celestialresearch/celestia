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
	"path"
	"strings"
	"unicode"
)

func architecturePathFindings(
	files []string, executables map[string]struct{}, policy architecturePolicy,
) []string {
	if collision := architectureCaseCollision(files); collision != "" {
		return []string{collision}
	}
	roots := stringSet(policy.RootDirectories)
	rootFiles := stringSet(policy.RootFiles)
	packages := stringSet(policy.Packages)
	rustPackages := stringSet(policy.RustPackages)
	scripts := stringSet(policy.Scripts)
	prohibited := stringSet(policy.Prohibited)
	prohibitedPaths := stringSet(policy.ProhibitedPaths)
	findings := splitSourcePathFindings(files)
	for _, file := range files {
		_, executable := executables[file]
		findings = append(findings, architectureFileFindings(
			file, executable, roots, rootFiles, packages, rustPackages, scripts,
			stringSet(policy.Commands), prohibited, prohibitedPaths,
		)...)
		if architectureFindingsFull(findings) {
			return boundedArchitectureFindings(findings)
		}
	}
	return findings
}

func architectureCaseCollision(files []string) string {
	seen := make(map[string]string, len(files))
	for _, file := range files {
		key := windowsFoldPath(file)
		if previous, exists := seen[key]; exists && previous != file {
			return fmt.Sprintf("%q: tracked path collides with %q", file, previous)
		}
		seen[key] = file
	}
	return ""
}

func windowsFoldPath(file string) string {
	var folded strings.Builder
	for _, character := range file {
		minimum := character
		for next := unicode.SimpleFold(character); next != character; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		folded.WriteRune(minimum)
	}
	return folded.String()
}

func architectureFileFindings(
	file string, executable bool,
	roots, rootFiles, packages, rustPackages, scripts, commands, prohibited, prohibitedPaths map[string]struct{},
) []string {
	if !validArchitecturePath(file) {
		return []string{fmt.Sprintf("%q: invalid tracked path", file)}
	}
	segments := strings.Split(file, "/")
	for root := range prohibitedPaths {
		if file == root || strings.HasPrefix(file, root+"/") {
			return []string{file + ": prohibited package path was recreated"}
		}
	}
	if len(segments) == 1 {
		if findings := architectureScriptPathFindings(file, executable, scripts); len(findings) != 0 {
			return findings
		}
		if _, allowed := rootFiles[file]; !allowed {
			return []string{file + ": undeclared root file"}
		}
		return nil
	}
	if _, allowed := roots[segments[0]]; !allowed {
		return []string{file + ": unapproved root directory"}
	}
	findings := prohibitedPathFindings(file, segments, prohibited)
	findings = append(findings, architectureOwnerPathFindings(
		file, segments[0], packages, rustPackages, scripts, commands,
	)...)
	findings = append(findings, architectureGoPathFindings(
		file, segments[0], packages, commands,
	)...)
	findings = append(findings, architectureScriptPathFindings(
		file, executable, scripts,
	)...)
	return append(findings, architectureRustPathFindings(file, rustPackages)...)
}

func architectureOwnerPathFindings(
	file, root string,
	packages, rustPackages, scripts, commands map[string]struct{},
) []string {
	var owners map[string]struct{}
	switch root {
	case ".github":
		if !strings.HasPrefix(file, ".github/scripts/") {
			return undeclaredRootSourceFinding(file)
		}
		if _, declared := scripts[file]; declared {
			return nil
		}
		return []string{file + ": script is not declared"}
	case "cmd":
		owners = commands
	case "internal", "tools":
		owners = packages
	case "worker":
		owners = rustPackages
	default:
		return undeclaredRootSourceFinding(file)
	}
	for owner := range owners {
		if architectureOwnerAccepts(file, root, owner) {
			return nil
		}
	}
	return []string{file + ": source owner is not declared"}
}

func undeclaredRootSourceFinding(file string) []string {
	if !architectureMaintainedSource(file) {
		return nil
	}
	return []string{file + ": source owner is not declared"}
}

func architectureOwnerAccepts(file, root, owner string) bool {
	if !strings.HasPrefix(file, owner+"/") {
		return false
	}
	return !architectureMaintainedSource(file) ||
		(root == "worker" && strings.EqualFold(path.Ext(file), ".rs")) ||
		path.Dir(file) == owner
}

func architectureMaintainedSource(file string) bool {
	switch strings.ToLower(path.Ext(file)) {
	case ".c", ".cc", ".cpp", ".cxx", ".f", ".f90", ".for", ".go", ".h",
		".hh", ".hpp", ".hxx", ".java", ".js", ".jsx", ".kt", ".kts", ".m",
		".proto", ".rs", ".s", ".sql", ".swift", ".swig", ".swigcxx", ".ts",
		".tsx", ".zig":
		return true
	default:
		base := path.Base(file)
		return base == "Dockerfile" || base == "Makefile"
	}
}

func architectureScriptPathFindings(
	file string, executable bool, scripts map[string]struct{},
) []string {
	extension := strings.ToLower(path.Ext(file))
	if !executable && !architectureScriptExtension(extension) {
		return nil
	}
	if _, declared := scripts[file]; declared {
		return nil
	}
	return []string{file + ": script is not declared"}
}

func architectureScriptExtension(extension string) bool {
	switch extension {
	case ".bash", ".bat", ".cmd", ".pl", ".ps1", ".py", ".rb", ".sh":
		return true
	default:
		return false
	}
}

func architectureRustPathFindings(file string, packages map[string]struct{}) []string {
	if path.Base(file) == "build.rs" {
		return []string{file + ": Cargo build scripts are prohibited"}
	}
	if file != "Cargo.toml" && path.Base(file) != "Cargo.toml" &&
		!strings.HasSuffix(file, ".rs") {
		return nil
	}
	for directory := range packages {
		if file == directory+"/Cargo.toml" ||
			strings.HasPrefix(file, directory+"/") && strings.HasSuffix(file, ".rs") {
			return nil
		}
	}
	if file == "Cargo.toml" {
		return nil
	}
	return []string{file + ": Rust package is not declared"}
}

func architectureGoPathFindings(
	file, root string, packages, commands map[string]struct{},
) []string {
	if strings.EqualFold(path.Ext(file), ".syso") {
		return []string{file + ": Go object files are prohibited"}
	}
	if !strings.HasSuffix(file, ".go") {
		return nil
	}
	directory := path.Dir(file)
	if root == "cmd" {
		if _, declared := commands[directory]; !declared {
			return []string{file + ": command is not declared"}
		}
		return nil
	}
	if _, declared := packages[directory]; !declared {
		return []string{file + ": Go package is not declared"}
	}
	return nil
}

func prohibitedPathFindings(
	file string, segments []string, prohibited map[string]struct{},
) []string {
	var findings []string
	for _, segment := range segments[1 : len(segments)-1] {
		if _, denied := prohibited[strings.ToLower(segment)]; denied {
			findings = append(findings, file+": prohibited directory segment "+segment)
			if architectureFindingsFull(findings) {
				return boundedArchitectureFindings(findings)
			}
		}
	}
	if strings.EqualFold(segments[len(segments)-1], "private-key.pem") {
		findings = append(findings, file+": private-key path is prohibited")
	}
	return findings
}
