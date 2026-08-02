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
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/modfile"
)

const (
	architecturePolicyPath  = "policies/architecture.json"
	maxArchitectureFindings = 16
	architectureTruncated   = "additional architecture findings omitted"
)

func runArchitecturePolicy(
	stderr io.Writer,
	inventory func() ([]string, error),
	executableInventory func([]string) ([]string, error),
	readFile func(string) ([]byte, error),
) int {
	return runArchitecturePolicyWithin(
		stderr, inventory, executableInventory, readFile,
		maxArchitectureDuration,
	)
}

type architectureEvaluation struct {
	findings []string
	err      error
}

func runArchitecturePolicyWithin(
	stderr io.Writer,
	inventory func() ([]string, error),
	executableInventory func([]string) ([]string, error),
	readFile func(string) ([]byte, error),
	duration time.Duration,
) int {
	result := make(chan architectureEvaluation, 1)
	go func() {
		findings, err := evaluateArchitecture(
			inventory, executableInventory, readFile,
		)
		result <- architectureEvaluation{findings: findings, err: err}
	}()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case evaluation := <-result:
		return architectureEvaluationStatus(stderr, evaluation)
	case <-timer.C:
		select {
		case evaluation := <-result:
			return architectureEvaluationStatus(stderr, evaluation)
		default:
		}
		writeArchitectureError(
			stderr, errors.New("architecture evaluation deadline exceeded"),
		)
		return 1
	}
}

func architectureEvaluationStatus(
	stderr io.Writer, evaluation architectureEvaluation,
) int {
	if evaluation.err != nil {
		writeArchitectureError(stderr, evaluation.err)
		return 1
	}
	if len(evaluation.findings) == 0 {
		return 0
	}
	writeArchitectureError(
		stderr, errors.New(strings.Join(evaluation.findings, "\n")),
	)
	return 1
}

func evaluateArchitecture(
	inventory func() ([]string, error),
	executableInventory func([]string) ([]string, error),
	readFile func(string) ([]byte, error),
) ([]string, error) {
	budget := newArchitectureReadBudget(readFile)
	files, err := inventory()
	if err != nil {
		return nil, fmt.Errorf("inventory architecture: %w", err)
	}
	if err := rejectModuleReplacements(files, budget.readFile); err != nil {
		return nil, err
	}
	executables, err := executableInventory(files)
	if err != nil {
		return nil, fmt.Errorf("inventory executable sources: %w", err)
	}
	policyData, err := budget.readFile(architecturePolicyPath)
	if err != nil {
		return nil, fmt.Errorf("read architecture policy: %w", err)
	}
	policy, err := decodeArchitecturePolicy(policyData)
	if err != nil {
		return nil, err
	}
	findings, err := architectureFindings(
		files, stringSet(executables), policy, budget.readFile,
	)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func writeArchitectureError(stderr io.Writer, err error) {
	message := err.Error()
	if len(message)+1 > maxSourceBytes {
		message = "architecture diagnostic exceeded its output bound"
	}
	if _, writeErr := fmt.Fprintln(stderr, message); writeErr != nil {
		return
	}
}

func architectureFindings(
	files []string,
	executables map[string]struct{},
	policy architecturePolicy,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	if err := validateCurrentModule(readFile, policy.ModulePath); err != nil {
		return nil, err
	}
	findings := architecturePathFindings(files, executables, policy)
	findings = append(findings, missingSplitSourceFindings(files)...)
	if architectureFindingsFull(findings) {
		return boundedArchitectureFindings(findings), nil
	}
	declarations, err := attemptSplitDeclarationFindings(files, readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, declarations...)
	if architectureFindingsFull(findings) {
		return boundedArchitectureFindings(findings), nil
	}
	shebangs, err := architectureShebangFindings(files, policy.Scripts, readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, shebangs...)
	if architectureFindingsFull(findings) {
		return boundedArchitectureFindings(findings), nil
	}
	imports, err := architectureImportFindings(files, readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, imports...)
	if architectureFindingsFull(findings) {
		return boundedArchitectureFindings(findings), nil
	}
	rustTargets, err := architectureRustTargetFindings(readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, rustTargets...)
	if architectureFindingsFull(findings) {
		return boundedArchitectureFindings(findings), nil
	}
	documentation, err := packageDocumentationFindings(files, policy, readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, documentation...)
	findings = boundedArchitectureFindings(findings)
	sort.Strings(findings)
	return findings, nil
}

func architectureFindingsFull(findings []string) bool {
	return len(findings) > maxArchitectureFindings
}

func boundedArchitectureFindings(findings []string) []string {
	bounded := slices.DeleteFunc(slices.Clone(findings), func(finding string) bool {
		return finding == architectureTruncated
	})
	truncated := len(bounded) != len(findings) || architectureFindingsFull(bounded)
	if !truncated {
		return findings
	}
	sort.Strings(bounded)
	bounded = bounded[:min(len(bounded), maxArchitectureFindings)]
	return append(bounded, architectureTruncated)
}

func validateCurrentModule(
	readFile func(string) ([]byte, error),
	expected string,
) error {
	data, err := readFile("go.mod")
	if err != nil {
		return fmt.Errorf("read module identity: %w", err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil || module.Module == nil || module.Module.Mod.Path != expected {
		return errors.New("go.mod: module identity contradicts architecture policy")
	}
	return nil
}

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

func packageDocumentationFindings(
	files []string,
	policy architecturePolicy,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	documented := make(map[string]bool, len(policy.Packages))
	for _, file := range files {
		if err := observePackageDocumentation(
			file, policy.Packages, documented, readFile,
		); err != nil {
			return nil, err
		}
	}
	var findings []string
	for _, directory := range policy.Packages {
		if !documented[directory] {
			findings = append(findings, directory+": package documentation is missing")
			if architectureFindingsFull(findings) {
				return boundedArchitectureFindings(findings), nil
			}
		}
	}
	return findings, nil
}

func observePackageDocumentation(
	file string,
	packages []string,
	documented map[string]bool,
	readFile func(string) ([]byte, error),
) error {
	if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
		return nil
	}
	directory := path.Dir(file)
	if documented[directory] || !slices.Contains(packages, directory) {
		return nil
	}
	if path.Base(file) != "doc.go" {
		return nil
	}
	source, err := readFile(file)
	if err != nil {
		return fmt.Errorf("read package documentation %s: %w", file, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, source, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse package documentation %s: %w", file, quotedDiagnostic(err))
	}
	if portablePackageDocumentation(file, source) && parsed.Doc != nil &&
		strings.HasPrefix(parsed.Doc.Text(), "Package "+parsed.Name.Name+" ") {
		documented[directory] = true
	}
	return nil
}

func portablePackageDocumentation(file string, source []byte) bool {
	name := strings.TrimSuffix(path.Base(file), ".go")
	for _, target := range policyBuildTargets {
		if strings.HasSuffix(name, "_"+target.goos) ||
			strings.HasSuffix(name, "_"+target.goarch) {
			return false
		}
	}
	for line := range bytes.SplitSeq(source, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("package ")) {
			return true
		}
		if bytes.HasPrefix(trimmed, []byte("//go:build")) ||
			bytes.HasPrefix(trimmed, []byte("// +build")) {
			return false
		}
	}
	return false
}
