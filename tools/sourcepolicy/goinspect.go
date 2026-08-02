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
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

type goPolicyInspector struct {
	loaded  *packages.Package
	sources map[string]bool
	found   []string
}

func (inspector *goPolicyInspector) findings() []string {
	for _, file := range inspector.loaded.Syntax {
		ast.Inspect(file, inspector.inspect)
	}
	return inspector.found
}

func (inspector *goPolicyInspector) inspect(node ast.Node) bool {
	switch value := node.(type) {
	case *ast.FuncDecl:
		return inspector.inspectFunction(value)
	case *ast.SelectorExpr:
		return inspector.inspectSelector(value)
	case *ast.Ident:
		return inspector.inspectIdentifier(value)
	case *ast.CallExpr:
		return inspector.inspectCall(value)
	case *ast.Comment:
		return inspector.inspectComment(value)
	default:
		return true
	}
}

func (inspector *goPolicyInspector) inspectComment(comment *ast.Comment) bool {
	position := inspector.loaded.Fset.PositionFor(comment.Pos(), false)
	if !inspector.sources[filepath.Clean(position.Filename)] {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(comment.Text), "//go:linkname") {
		inspector.add(comment, "Go tests must not use go:linkname")
	}
	return false
}

func (inspector *goPolicyInspector) inspectFunction(function *ast.FuncDecl) bool {
	position := inspector.loaded.Fset.PositionFor(function.Pos(), false)
	if inspector.loaded.Name == "main" &&
		function.Name.Name == "main" &&
		!strings.HasSuffix(position.Filename, "_test.go") {
		return false
	}
	if !strings.HasSuffix(position.Filename, "_test.go") ||
		function.Name.Name != "TestMain" ||
		!isTestingMain(function, inspector.loaded.TypesInfo) {
		return true
	}
	if !validTestMainSyntax(function, inspector.loaded.TypesInfo) {
		inspector.add(function, "TestMain violates the local execution syntax")
	}
	return false
}

func (inspector *goPolicyInspector) inspectSelector(selector *ast.SelectorExpr) bool {
	if isTestingSkip(selector, inspector.loaded.TypesInfo) {
		inspector.add(selector, "Go tests must not skip cases")
		return true
	}
	if isRawSyscallFunction(selector, inspector.loaded.TypesInfo) {
		inspector.add(selector, "Go tests must not use raw system calls")
		return false
	}
	if isProcessResolverFunction(selector, inspector.loaded.TypesInfo) {
		inspector.add(selector, "Go tests must not alias system procedure resolution")
		return false
	}
	if isProcessExitFunction(selector, inspector.loaded.TypesInfo) {
		inspector.add(selector, "Go tests must not alias process exit")
		return false
	}
	return true
}

func (inspector *goPolicyInspector) inspectIdentifier(identifier *ast.Ident) bool {
	if inspector.isExecutableMainReference(identifier) {
		inspector.add(identifier, "Go tests must not reference executable main")
		return false
	}
	if isRawSyscallFunction(identifier, inspector.loaded.TypesInfo) {
		inspector.add(identifier, "Go tests must not use raw system calls")
		return false
	}
	if isProcessResolverFunction(identifier, inspector.loaded.TypesInfo) {
		inspector.add(identifier, "Go tests must not alias system procedure resolution")
		return false
	}
	if !isProcessExitFunction(identifier, inspector.loaded.TypesInfo) {
		return true
	}
	inspector.add(identifier, "Go tests must not alias process exit")
	return false
}

func (inspector *goPolicyInspector) inspectCall(call *ast.CallExpr) bool {
	if inspector.isExecutableMainCall(call) {
		inspector.add(call, "Go tests must not invoke executable main")
		return false
	}
	if isSuccessfulTerminateProcessCall(call, inspector.loaded.TypesInfo) {
		inspector.add(call, "Go tests must not terminate the test process")
		return false
	}
	if isTerminateProcessCall(call, inspector.loaded.TypesInfo) {
		return false
	}
	if isDynamicProcessExitResolution(call, inspector.loaded.TypesInfo) {
		inspector.add(call, "Go tests must not resolve process exit dynamically")
		return false
	}
	if isProcessResolverFunction(call.Fun, inspector.loaded.TypesInfo) {
		return false
	}
	if !isProcessExit(call, inspector.loaded.TypesInfo) {
		return true
	}
	if !nonzeroExitCode(call.Args[0]) {
		inspector.add(call, "Go tests must not exit successfully")
	}
	return false
}

func (inspector *goPolicyInspector) add(node ast.Node, message string) {
	position := inspector.loaded.Fset.PositionFor(node.Pos(), false)
	inspector.found = append(inspector.found, fmt.Sprintf(
		"%s:%d: %s",
		filepath.ToSlash(position.Filename),
		position.Line,
		message,
	))
}
