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
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	attemptSplitDirectory  = "internal/operation/urlreference/attempt/"
	attemptSplitPackageSHA = "41b08fd475b7651104ebff3d729e86f36dd4d320c5acc096450fcfb67dd32f3e"
	attemptSplitSourceSHA  = "df172c96f1b8459e9a01cb33a96194f5b5455a4ac92a04e7617fb54eb6ed8239"
	attemptSplitTargetSHA  = "83647732c94534e08715e7fba2178797aa926f5cb9bc5db44358a688fa742ee9"
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
	for _, file := range goFiles {
		source, err := readFile(file)
		if err != nil {
			return attemptSplitInventory{}, fmt.Errorf("read attempt split source %s: %w", file, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, source, parser.ParseComments)
		if err != nil {
			return attemptSplitInventory{}, fmt.Errorf("parse attempt split source %s: %w", file, err)
		}
		if parsed.Name.Name != "attemptstore" {
			return attemptSplitInventory{}, fmt.Errorf("attempt split source %s uses package %s", file, parsed.Name.Name)
		}
		build, err := goBuildConstraint(source)
		if err != nil {
			return attemptSplitInventory{}, fmt.Errorf("parse attempt split build constraint %s: %w", file, err)
		}
		packages = append(packages, file+"\x00"+parsed.Name.Name+"\x00"+build)
		for _, declaration := range parsed.Decls {
			records, target, inventoryErr := goSplitDeclarationInventory(file, declaration)
			if inventoryErr != nil {
				return attemptSplitInventory{}, inventoryErr
			}
			for _, record := range records {
				sources = append(sources, file+"\x00"+record)
			}
			if target != "" {
				targets = append(targets, file+"\x00"+target)
			}
		}
	}
	return attemptSplitInventory{
		packages: hashInventory(packages),
		sources:  hashInventory(sources),
		targets:  hashInventory(targets),
	}, nil
}

func goBuildConstraint(source []byte) (string, error) {
	var expression string
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build") {
			if expression != "" {
				return "", fmt.Errorf("multiple //go:build lines")
			}
			expression = trimmed
		}
		if strings.HasPrefix(trimmed, "// +build") {
			return "", fmt.Errorf("legacy // +build constraint")
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	if expression == "" {
		return "portable", nil
	}
	parsed, err := constraint.Parse(expression)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
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
		identity := "func:" + receiver + value.Name.Name
		record := identity + "\x00" + signature
		if receiver == "" && isGoTestTarget(value.Name.Name) {
			return []string{record}, value.Name.Name + "\x00" + signature, nil
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
		return []string{"type:" + value.Name.Name + "\x00" + rendered}, nil
	case *ast.ValueSpec:
		records := make([]string, 0, len(value.Names))
		for _, name := range value.Names {
			records = append(records, kind+":"+name.Name+"\x00"+rendered)
		}
		return records, nil
	case *ast.ImportSpec:
		return []string{"import:" + rendered + "\x00" + rendered}, nil
	default:
		return nil, fmt.Errorf("unsupported specification %T", specification)
	}
}

func isGoTestTarget(name string) bool {
	for _, prefix := range []string{"Test", "Fuzz", "Benchmark"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(name, prefix)
		if remainder == "" {
			return true
		}
		next, _ := utf8.DecodeRuneInString(remainder)
		return !unicode.IsLower(next)
	}
	return false
}

func renderGoNode(node any) (string, error) {
	var rendered bytes.Buffer
	if err := format.Node(&rendered, token.NewFileSet(), node); err != nil {
		return "", err
	}
	return rendered.String(), nil
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
