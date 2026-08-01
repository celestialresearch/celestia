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
	"go/parser"
	"go/token"
	"path"
	"slices"
	"strconv"
	"strings"
)

const supervisionQualificationTest = "internal/processsupervision/supervisor_windows_test.go"

func architectureImportFindings(
	files []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	var findings []string
	for _, file := range files {
		if !strings.HasSuffix(file, ".go") {
			continue
		}
		source, err := readFile(file)
		if err != nil {
			return nil, fmt.Errorf("read imports %s: %w", file, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, source, parser.ImportsOnly)
		if err != nil {
			return nil, fmt.Errorf("parse imports %s: %w", file, err)
		}
		for _, specification := range parsed.Imports {
			imported, err := strconv.Unquote(specification.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("parse import path %s: %w", file, err)
			}
			reason := forbiddenArchitectureImport(path.Dir(file), imported)
			if file == supervisionQualificationTest {
				reason = forbiddenSupervisionQualificationImport(imported)
			}
			if reason != "" {
				findings = append(findings, file+": "+reason)
				if architectureFindingsFull(findings) {
					return boundedArchitectureFindings(findings), nil
				}
			}
		}
	}
	return findings, nil
}

func forbiddenSupervisionQualificationImport(imported string) string {
	if reason := forbiddenExternalArchitectureImport(imported); reason != "" {
		return reason
	}
	allowed := []string{
		architectureModule + "/internal/processsupervision",
		architectureModule + "/internal/urladmission",
		architectureModule + "/internal/urlreferencev1",
		architectureModule + "/internal/workerprotocolv1",
	}
	if slices.Contains(allowed, imported) ||
		!strings.HasPrefix(imported, architectureModule+"/internal/") {
		return ""
	}
	return "supervision qualification test imports an undeclared Production owner"
}

func forbiddenArchitectureImport(importer, imported string) string {
	if reason := forbiddenExternalArchitectureImport(imported); reason != "" {
		return reason
	}
	relative := strings.TrimPrefix(imported, architectureModule+"/")
	if relative == imported {
		return ""
	}
	importer = normaliseArchitecturePath(importer)
	relative = normaliseArchitecturePath(relative)
	if strings.HasPrefix(importer, "internal/execution/") &&
		strings.HasPrefix(relative, "internal/operation/") {
		return "execution packages must not import operations"
	}
	if reason := forbiddenCommandImport(importer, relative); reason != "" {
		return reason
	}
	return forbiddenOperationImport(importer, relative)
}

func normaliseArchitecturePath(value string) string {
	for _, migration := range expectedMigrationRoots() {
		if value == migration.Path {
			return migration.Destination
		}
		if strings.HasPrefix(value, migration.Path+"/") {
			return migration.Destination + strings.TrimPrefix(value, migration.Path)
		}
	}
	return value
}

func forbiddenCommandImport(importer, imported string) string {
	if !strings.HasPrefix(importer, "cmd/") ||
		!strings.HasPrefix(imported, "internal/operation/") {
		return ""
	}
	if len(strings.Split(imported, "/")) != 3 {
		return "commands must import an operation root, not its subpackages"
	}
	return ""
}

func forbiddenOperationImport(importer, imported string) string {
	if reason := forbiddenURLReferenceImport(importer, imported); reason != "" {
		return reason
	}
	operation := operationPath(importer)
	importedOperation := operationPath(imported)
	if operation == "" || importedOperation == "" {
		return ""
	}
	if operation != importedOperation {
		return "operation packages must not import another operation"
	}
	if importer != operation && imported == operation {
		return "operation subpackages must not import their orchestration root"
	}
	return ""
}

func forbiddenURLReferenceImport(importer, imported string) string {
	const root = "internal/operation/urlreference"
	if importer == root || !strings.HasPrefix(importer, root+"/") ||
		!strings.HasPrefix(imported, "internal/") {
		return ""
	}
	allowed := map[string][]string{
		root + "/attempt":   {root + "/admission", root + "/protocol", root + "/transform"},
		root + "/admission": {root + "/protocol", root + "/transform"},
		root + "/protocol":  {root + "/transform"},
		root + "/transform": {},
	}
	for _, dependency := range allowed[importer] {
		if imported == dependency || strings.HasPrefix(imported, dependency+"/") {
			return ""
		}
	}
	return "URL-reference subpackage imports a forbidden Production owner"
}

func forbiddenExternalArchitectureImport(imported string) string {
	if imported == "celestia.research/assurance" ||
		strings.HasPrefix(imported, "celestia.research/assurance/") {
		return "Production must not import Assurance"
	}
	if imported == architectureModule+"/tools" ||
		strings.HasPrefix(imported, architectureModule+"/tools/") {
		return "Production runtime must not import repository tools"
	}
	if imported == architectureModule+"/worker" ||
		strings.HasPrefix(imported, architectureModule+"/worker/") {
		return "Production runtime must not import worker source"
	}
	return ""
}

func operationPath(value string) string {
	const prefix = "internal/operation/"
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	remainder := strings.TrimPrefix(value, prefix)
	name, _, _ := strings.Cut(remainder, "/")
	if name == "" {
		return ""
	}
	return prefix + name
}
