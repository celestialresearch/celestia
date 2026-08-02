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
	"errors"
	"fmt"
	"slices"
	"sort"

	"golang.org/x/mod/modfile"
)

const (
	architecturePolicyPath  = "policies/architecture.json"
	maxArchitectureFindings = 16
	architectureTruncated   = "additional architecture findings omitted"
)

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
