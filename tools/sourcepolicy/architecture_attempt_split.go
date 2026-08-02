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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/doc"
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"sort"
	"strings"
)

const (
	attemptSplitDirectory  = "internal/operation/urlreference/attempt/"
	maxAttemptSplitBytes   = 16 << 20
	attemptSplitPackageSHA = "192a264c5ee60a59a1b5a6fcb9badd0460e41516c6c9b01d0d43e09fbb362438"
	attemptSplitSourceSHA  = "221f0f88934d7f53a7ee31a68c53457f942ddbee5439ac894538ac74d9f1f51d"
	attemptSplitTargetSHA  = "9c5e90825b7c98d77e3ba643f070c13da1fa7c4edc4937054682bf0e20309e8f"
)

type attemptSplitInventory struct {
	packages string
	sources  string
	targets  string
}

func attemptSplitDeclarationFindings(
	files []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	inventory, err := attemptSplitInventoryFor(files, readFile)
	if err != nil {
		return nil, err
	}
	var findings []string
	for label, pair := range map[string][2]string{
		"package and build": {inventory.packages, attemptSplitPackageSHA},
		"source":            {inventory.sources, attemptSplitSourceSHA},
		"test target":       {inventory.targets, attemptSplitTargetSHA},
	} {
		if pair[0] != pair[1] {
			findings = append(findings, fmt.Sprintf(
				"%s: %s inventory differs: %s",
				strings.TrimSuffix(attemptSplitDirectory, "/"), label, pair[0],
			))
		}
	}
	sort.Strings(findings)
	return findings, nil
}

func attemptSplitInventoryFor(
	files []string,
	readFile func(string) ([]byte, error),
) (attemptSplitInventory, error) {
	goFiles := slices.DeleteFunc(slices.Clone(files), func(file string) bool {
		return !strings.HasPrefix(file, attemptSplitDirectory) || path.Ext(file) != ".go"
	})
	sort.Strings(goFiles)
	packages := make([]string, 0, len(goFiles))
	sources := make([]string, 0, len(goFiles)*4)
	targets := make([]string, 0, len(goFiles))
	total := 0
	for _, file := range goFiles {
		source, err := readFile(file)
		if err != nil {
			return attemptSplitInventory{}, fmt.Errorf("read attempt split source %s: %w", file, err)
		}
		total += len(source)
		if total > maxAttemptSplitBytes {
			return attemptSplitInventory{}, fmt.Errorf("attempt split source inventory exceeds bound")
		}
		positions := token.NewFileSet()
		parsed, err := parser.ParseFile(positions, file, source, parser.ParseComments)
		if err != nil {
			return attemptSplitInventory{}, fmt.Errorf("parse attempt split source %s: %w", file, err)
		}
		if parsed.Name.Name != "attemptstore" {
			return attemptSplitInventory{}, fmt.Errorf("attempt split source %s uses package %s", file, parsed.Name.Name)
		}
		build, err := goBuildConstraint(source, positions, parsed)
		if err != nil {
			return attemptSplitInventory{}, fmt.Errorf("parse attempt split build constraint %s: %w", file, err)
		}
		packages = append(packages, inventoryRecord("package", file, parsed.Name.Name, build))
		for _, declaration := range parsed.Decls {
			records, target, inventoryErr := goSplitDeclarationInventory(file, declaration)
			if inventoryErr != nil {
				return attemptSplitInventory{}, inventoryErr
			}
			for _, record := range records {
				sources = append(sources, inventoryRecord("source", file, record))
			}
			if target != "" {
				targets = append(targets, inventoryRecord("target", file, target))
			}
		}
		for _, example := range doc.Examples(parsed) {
			if example.Output != "" || example.EmptyOutput {
				targets = append(targets, inventoryRecord("example-target", file, example.Name))
			}
		}
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

func goBuildConstraint(source []byte, positions *token.FileSet, parsed *ast.File) (string, error) {
	var expression string
	positionFile := positions.File(parsed.Pos())
	for _, group := range parsed.Comments {
		for _, comment := range group.List {
			if comment.Pos() > parsed.Package {
				continue
			}
			if strings.HasPrefix(comment.Text, "// +build") {
				return "", fmt.Errorf("legacy // +build constraint")
			}
			if !strings.HasPrefix(comment.Text, "//go:build") {
				continue
			}
			if expression != "" {
				return "", fmt.Errorf("multiple //go:build lines")
			}
			tail := bytes.ReplaceAll(
				source[positionFile.Offset(comment.End()):positionFile.Offset(parsed.Package)],
				[]byte("\r\n"), []byte("\n"),
			)
			if !bytes.HasPrefix(tail, []byte("\n\n")) {
				return "", fmt.Errorf("//go:build constraint is not followed by a blank line")
			}
			expression = comment.Text
		}
	}
	if expression == "" {
		return "portable", nil
	}
	expressionValue, err := constraint.Parse(expression)
	if err != nil {
		return "", err
	}
	return expressionValue.String(), nil
}

func goSplitDeclarationInventory(file string, declaration ast.Decl) ([]string, string, error) {
	switch value := declaration.(type) {
	case *ast.FuncDecl:
		receiver := ""
		if value.Recv != nil {
			var err error
			receiver, err = renderGoNode(value.Recv.List[0].Type)
			if err != nil {
				return nil, "", fmt.Errorf("render receiver in %s: %w", file, err)
			}
		}
		signature, err := renderGoNode(value.Type)
		if err != nil {
			return nil, "", fmt.Errorf("render function signature in %s: %w", file, err)
		}
		kind := "free-function"
		if receiver != "" {
			kind = "method"
		}
		record := inventoryRecord(kind, receiver, value.Name.Name, signature)
		if receiver == "" && isGoTestTarget(value.Name.Name) {
			return []string{record}, inventoryRecord("go-test", value.Name.Name, signature), nil
		}
		return []string{record}, "", nil
	case *ast.GenDecl:
		var records []string
		for _, specification := range value.Specs {
			specRecords, err := goSplitSpecificationInventory(value.Tok.String(), specification)
			if err != nil {
				return nil, "", fmt.Errorf("render declaration in %s: %w", file, err)
			}
			records = append(records, specRecords...)
		}
		return records, "", nil
	default:
		return nil, "", fmt.Errorf("unsupported declaration in %s", file)
	}
}

func goSplitSpecificationInventory(kind string, specification ast.Spec) ([]string, error) {
	rendered, err := renderGoNode(specification)
	if err != nil {
		return nil, err
	}
	switch value := specification.(type) {
	case *ast.TypeSpec:
		return []string{inventoryRecord("type", value.Name.Name, rendered)}, nil
	case *ast.ValueSpec:
		records := make([]string, 0, len(value.Names))
		for _, name := range value.Names {
			records = append(records, inventoryRecord(kind, name.Name, rendered))
		}
		return records, nil
	case *ast.ImportSpec:
		return []string{inventoryRecord("import", rendered)}, nil
	default:
		return nil, fmt.Errorf("unsupported specification %T", specification)
	}
}

func isGoTestTarget(name string) bool {
	return name == "TestMain" || validGoTestName(name) || validGoBenchmarkName(name)
}

func validGoBenchmarkName(name string) bool {
	return strings.HasPrefix(name, "Benchmark") &&
		validGoTestName("Test"+strings.TrimPrefix(name, "Benchmark"))
}

func renderGoNode(node any) (string, error) {
	var rendered bytes.Buffer
	if err := format.Node(&rendered, token.NewFileSet(), node); err != nil {
		return "", err
	}
	return rendered.String(), nil
}

func inventoryRecord(kind string, fields ...string) string {
	var record bytes.Buffer
	writeInventoryField := func(field string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		record.Write(length[:])
		record.WriteString(field)
	}
	writeInventoryField(kind)
	for _, field := range fields {
		writeInventoryField(field)
	}
	return record.String()
}

func hashInventory(records []string) string {
	hash := sha256.New()
	var length [8]byte
	for _, record := range records {
		binary.BigEndian.PutUint64(length[:], uint64(len(record)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(record))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
