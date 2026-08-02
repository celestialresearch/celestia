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
	"strings"
	"time"
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

func writeArchitectureError(stderr io.Writer, err error) {
	message := err.Error()
	if len(message)+1 > maxSourceBytes {
		message = "architecture diagnostic exceeded its output bound"
	}
	if _, writeErr := fmt.Fprintln(stderr, message); writeErr != nil {
		return
	}
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
