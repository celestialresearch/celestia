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
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	supervisionSplitDirectory  = "internal/execution/supervision/"
	maxSupervisionSplitBytes   = 16 << 20
	supervisionSplitPackageSHA = "eb7c1708a470fd614025a75081168a20efbd51f2207d003d29e57a97eaa41843"
	supervisionSplitSourceSHA  = "02fcad48062f509aa9da56cab6f6ef662f74ec3c5115d2be5ce6eea01ac0f7f5"
	supervisionSplitTargetSHA  = "d1a257b599cd2a7eb2367b7f26ef81e99f0aedcd36548d1e71e7090536d7ad31"
	supervisionStartBodySHA    = "8d88e58ec4bc67bb6e6cac752d6bda1d5e6cc4411b4c2531cc3ea0583c523485"
	supervisionStartFile       = supervisionSplitDirectory + "process_start_windows.go"
	supervisionStartFunction   = "startSuspendedWith"
)

var supervisionSplitOwners = map[string]string{
	"cleanup_windows.go":                  "cleanup",
	"cleanup_windows_test.go":             "cleanup",
	"container_errors_windows_test.go":    "launch",
	"container_fault_windows_test.go":     "launch",
	"doc.go":                              "contract",
	"environment_windows_test.go":         "launch",
	"image_errors_windows_test.go":        "image",
	"image_windows.go":                    "image",
	"image_windows_test.go":               "image",
	"launch_preparation_windows_test.go":  "launch",
	"launch_windows.go":                   "launch",
	"native_fault_windows_test.go":        "native",
	"native_layout_windows_test.go":       "native",
	"native_pointer_windows.go":           "native",
	"native_stream_windows_test.go":       "native",
	"native_test_helpers_windows_test.go": "native",
	"native_wait_windows_test.go":         "native",
	"native_windows.go":                   "native",
	"observation_windows.go":              "observation",
	"outcome_windows.go":                  "outcome",
	"outcome_windows_test.go":             "outcome",
	"pipes_windows.go":                    "streams",
	"process_start_fault_windows_test.go": "startup",
	"process_start_windows.go":            "startup",
	"process_tree_windows_test.go":        "qualification",
	"resource_close_windows_test.go":      "resources",
	"resources_windows.go":                "resources",
	"runtime_windows.go":                  "launch",
	"startup_cleanup_windows_test.go":     "cleanup",
	"stream_result_windows_test.go":       "streams",
	"stream_windows.go":                   "streams",
	"supervisor.go":                       "contract",
	"supervisor_unsupported.go":           "platform",
	"supervisor_unsupported_test.go":      "platform",
	"supervisor_windows.go":               "orchestration",
	"supervisor_windows_test.go":          "qualification",
	"timing_windows.go":                   "timing",
	"wait_windows.go":                     "wait",
	"wait_windows_test.go":                "wait",
}

func supervisionSplitDeclarationFindings(
	files []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	inventory, err := supervisionSplitInventoryFor(files, readFile, supervisionSplitOwners)
	if err != nil {
		return nil, err
	}
	var findings []string
	for label, pair := range map[string][2]string{
		"package, build and owner": {inventory.packages, supervisionSplitPackageSHA},
		"source":                   {inventory.sources, supervisionSplitSourceSHA},
		"test target":              {inventory.targets, supervisionSplitTargetSHA},
	} {
		if pair[0] != pair[1] {
			findings = append(findings, fmt.Sprintf(
				"%s: %s inventory differs: %s",
				strings.TrimSuffix(supervisionSplitDirectory, "/"), label, pair[0],
			))
		}
	}
	bodySHA, err := supervisionStartBodyInventory(readFile)
	if err != nil {
		return nil, err
	}
	if bodySHA != supervisionStartBodySHA {
		findings = append(findings, fmt.Sprintf(
			"%s: suspended start body differs: %s",
			strings.TrimSuffix(supervisionSplitDirectory, "/"), bodySHA,
		))
	}
	sort.Strings(findings)
	return findings, nil
}

func supervisionStartBodyInventory(readFile func(string) ([]byte, error)) (string, error) {
	source, err := readFile(supervisionStartFile)
	if err != nil {
		return "", fmt.Errorf("read supervision start source: %w", quotedDiagnostic(err))
	}
	parsed, err := parser.ParseFile(
		token.NewFileSet(), strconv.Quote(supervisionStartFile), source, 0,
	)
	if err != nil {
		return "", fmt.Errorf("parse supervision start source: %w", quotedDiagnostic(err))
	}
	var body string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != supervisionStartFunction {
			continue
		}
		if body != "" || function.Body == nil {
			return "", errors.New("supervision start declaration is invalid")
		}
		body, err = renderGoNode(function.Body)
		if err != nil {
			return "", fmt.Errorf("render supervision start body: %w", err)
		}
	}
	if body == "" {
		return "", errors.New("supervision start declaration is missing")
	}
	return hashInventory([]string{
		inventoryRecord("declaration-body", supervisionStartFile, supervisionStartFunction, body),
	}), nil
}

func supervisionSplitInventoryFor(
	files []string,
	readFile func(string) ([]byte, error),
	owners map[string]string,
) (attemptSplitInventory, error) {
	return ownedGoSplitInventoryFor(files, readFile, ownedGoSplitSpec{
		directory: supervisionSplitDirectory,
		packages:  []string{"supervision", "supervision_test"},
		owners:    owners,
		maxBytes:  maxSupervisionSplitBytes,
		label:     "supervision",
	})
}

type ownedGoSplitSpec struct {
	directory        string
	packages         []string
	owners           map[string]string
	maxBytes         int
	label            string
	bindTargetBodies bool
}

func ownedGoSplitInventoryFor(
	files []string,
	readFile func(string) ([]byte, error),
	spec ownedGoSplitSpec,
) (attemptSplitInventory, error) {
	goFiles := slices.DeleteFunc(slices.Clone(files), func(file string) bool {
		return !strings.HasPrefix(file, spec.directory)
	})
	sort.Strings(goFiles)
	if len(goFiles) != len(spec.owners) {
		return attemptSplitInventory{
			packages: hashInventory([]string{inventoryRecord("file-count", strconv.Itoa(len(goFiles)))}),
		}, nil
	}
	packages := make([]string, 0, len(goFiles))
	sources := make([]string, 0, len(goFiles)*4)
	targets := make([]string, 0, len(goFiles))
	total := 0
	for _, file := range goFiles {
		name := strings.TrimPrefix(file, spec.directory)
		owner, ok := spec.owners[name]
		if !ok || path.Ext(file) != ".go" {
			return attemptSplitInventory{
				packages: hashInventory([]string{inventoryRecord("unexpected-file", file)}),
			}, nil
		}
		inventory, err := ownedGoSplitFileInventoryFor(file, owner, readFile, spec)
		if err != nil {
			return attemptSplitInventory{}, err
		}
		total += inventory.bytes
		if total > spec.maxBytes {
			return attemptSplitInventory{}, fmt.Errorf("%s split source inventory exceeds bound", spec.label)
		}
		packages = append(packages, inventory.packages...)
		sources = append(sources, inventory.sources...)
		targets = append(targets, inventory.targets...)
	}
	sort.Strings(packages)
	sort.Strings(sources)
	sort.Strings(targets)
	return attemptSplitInventory{
		packages: hashInventory(packages),
		sources:  hashInventory(sources),
		targets:  hashInventory(targets),
	}, nil
}

func ownedGoSplitFileInventoryFor(
	file string,
	owner string,
	readFile func(string) ([]byte, error),
	spec ownedGoSplitSpec,
) (attemptSplitFileInventory, error) {
	source, err := readFile(file)
	if err != nil {
		return attemptSplitFileInventory{}, fmt.Errorf(
			"read %s split source %q: %w", spec.label, file, quotedDiagnostic(err),
		)
	}
	positions := token.NewFileSet()
	parsed, err := parser.ParseFile(positions, strconv.Quote(file), source, parser.ParseComments)
	if err != nil {
		return attemptSplitFileInventory{}, fmt.Errorf(
			"parse %s split source %q: %w", spec.label, file, quotedDiagnostic(err),
		)
	}
	if !slices.Contains(spec.packages, parsed.Name.Name) {
		return attemptSplitFileInventory{}, fmt.Errorf(
			"%s split source %q uses package %s", spec.label, file, parsed.Name.Name,
		)
	}
	build, err := goBuildConstraint(source, positions, parsed)
	if err != nil {
		return attemptSplitFileInventory{}, fmt.Errorf(
			"parse %s split build constraint %q: %w", spec.label, file, quotedDiagnostic(err),
		)
	}
	inventory := attemptSplitFileInventory{
		packages: []string{inventoryRecord("package", file, owner, parsed.Name.Name, build)},
		bytes:    len(source),
	}
	return ownedGoSplitDeclarations(file, parsed, inventory, spec.bindTargetBodies)
}

func ownedGoSplitDeclarations(
	file string,
	parsed *ast.File,
	inventory attemptSplitFileInventory,
	bindTargetBodies bool,
) (attemptSplitFileInventory, error) {
	for _, declaration := range parsed.Decls {
		records, target, inventoryErr := goSplitDeclarationInventory(file, declaration)
		if inventoryErr != nil {
			return attemptSplitFileInventory{}, inventoryErr
		}
		for _, record := range records {
			inventory.sources = append(inventory.sources, inventoryRecord("source", file, record))
		}
		if bindTargetBodies && target != "" {
			rendered, err := renderGoNode(declaration)
			if err != nil {
				return attemptSplitFileInventory{}, fmt.Errorf(
					"render declaration in %q: %w", file, err,
				)
			}
			inventory.sources = append(
				inventory.sources, inventoryRecord("declaration", file, rendered),
			)
			target = inventoryRecord("test-declaration", target, rendered)
		}
		if target != "" {
			inventory.targets = append(inventory.targets, inventoryRecord("target", file, target))
		}
	}
	for _, example := range doc.Examples(parsed) {
		if example.Output != "" || example.EmptyOutput {
			inventory.targets = append(
				inventory.targets, inventoryRecord("example-target", file, example.Name),
			)
		}
	}
	return inventory, nil
}
