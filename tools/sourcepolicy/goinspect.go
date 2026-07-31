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
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

type goPolicyInspector struct {
	loaded *packages.Package
	found  []string
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
	if !isProcessExitFunction(identifier, inspector.loaded.TypesInfo) {
		return true
	}
	inspector.add(identifier, "Go tests must not alias process exit")
	return false
}

func (inspector *goPolicyInspector) isExecutableMainReference(
	identifier *ast.Ident,
) bool {
	if inspector.loaded.Name != "main" || identifier.Name != "main" {
		return false
	}
	function, ok := inspector.loaded.TypesInfo.Uses[identifier].(*types.Func)
	return ok && inspector.loaded.Types != nil &&
		function.Pkg() == inspector.loaded.Types
}

func (inspector *goPolicyInspector) inspectCall(call *ast.CallExpr) bool {
	if inspector.isExecutableMainCall(call) {
		inspector.add(call, "Go tests must not invoke executable main")
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

func (inspector *goPolicyInspector) isExecutableMainCall(call *ast.CallExpr) bool {
	position := inspector.loaded.Fset.PositionFor(call.Pos(), false)
	if inspector.loaded.Name != "main" ||
		!strings.HasSuffix(position.Filename, "_test.go") {
		return false
	}
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || identifier.Name != "main" {
		return false
	}
	function, ok := inspector.loaded.TypesInfo.Uses[identifier].(*types.Func)
	return ok && function.Pkg() == inspector.loaded.Types
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

func validTestMainSyntax(function *ast.FuncDecl, info *types.Info) bool {
	if function.Body == nil || len(function.Body.List) == 0 ||
		testMainSyntaxBypass(function.Body.List[:len(function.Body.List)-1], info) {
		return false
	}
	expression, ok := function.Body.List[len(function.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return false
	}
	exitCall, ok := expression.X.(*ast.CallExpr)
	if !ok || !isOSExit(exitCall, info) {
		return false
	}
	return isTestingRun(exitCall.Args[0], info)
}

func testMainSyntaxBypass(statements []ast.Stmt, info *types.Info) bool {
	bypass := false
	for _, statement := range statements {
		ast.Inspect(statement, func(node ast.Node) bool {
			if bypass {
				return false
			}
			if function, ok := node.(*ast.FuncLit); ok {
				if containsSuccessfulExit(function.Body, info) {
					bypass = true
				}
				return false
			}
			if _, ok := node.(*ast.ReturnStmt); ok {
				bypass = true
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !isOSExit(call, info) {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && isTestingMRun(info.Uses[selector.Sel]) {
					bypass = true
					return false
				}
				return true
			}
			if !nonzeroExitCode(call.Args[0]) {
				bypass = true
			}
			return true
		})
	}
	return bypass
}

func containsSuccessfulExit(node ast.Node, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if ok && isOSExit(call, info) && !nonzeroExitCode(call.Args[0]) {
			found = true
		}
		return true
	})
	return found
}

func nonzeroExitCode(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return false
	}
	value, err := strconv.ParseInt(literal.Value, 0, 64)
	return err == nil && value != 0
}

func isTestingMain(function *ast.FuncDecl, info *types.Info) bool {
	object, ok := info.Defs[function.Name].(*types.Func)
	if !ok {
		return false
	}
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Params().Len() != 1 || signature.Results().Len() != 0 {
		return false
	}
	pointer, ok := signature.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "testing" &&
		named.Obj().Name() == "M"
}

func isOSExit(call *ast.CallExpr, info *types.Info) bool {
	return len(call.Args) == 1 && isOSExitFunction(call.Fun, info)
}

func isProcessExit(call *ast.CallExpr, info *types.Info) bool {
	return len(call.Args) == 1 && isProcessExitFunction(call.Fun, info)
}

func isProcessExitFunction(expression ast.Expr, info *types.Info) bool {
	if isOSExitFunction(expression, info) {
		return true
	}
	object := functionObject(expression, "Exit", info)
	if object == nil || object.Pkg() == nil {
		return false
	}
	return object.Pkg().Path() == "syscall" ||
		object.Pkg().Path() == "golang.org/x/sys/windows" ||
		object.Pkg().Path() == "golang.org/x/sys/unix" ||
		object.Pkg().Path() == "golang.org/x/sys/plan9"
}

func isRawSyscallFunction(expression ast.Expr, info *types.Info) bool {
	object := expressionFunction(expression, info)
	if object == nil || object.Pkg() == nil {
		return false
	}
	name := object.Name()
	if !strings.HasPrefix(name, "Syscall") &&
		!strings.HasPrefix(name, "RawSyscall") {
		return false
	}
	switch object.Pkg().Path() {
	case "syscall",
		"golang.org/x/sys/windows",
		"golang.org/x/sys/unix",
		"golang.org/x/sys/plan9":
		return true
	default:
		return false
	}
}

func isOSExitFunction(expression ast.Expr, info *types.Info) bool {
	object := functionObject(expression, "Exit", info)
	return object != nil && object.Pkg() != nil && object.Pkg().Path() == "os"
}

func functionObject(
	expression ast.Expr,
	name string,
	info *types.Info,
) *types.Func {
	function := expressionFunction(expression, info)
	if function == nil || function.Name() != name {
		return nil
	}
	return function
}

func expressionFunction(
	expression ast.Expr,
	info *types.Info,
) *types.Func {
	var object types.Object
	switch exit := expression.(type) {
	case *ast.SelectorExpr:
		object = info.Uses[exit.Sel]
	case *ast.Ident:
		object = info.Uses[exit]
	default:
		return nil
	}
	function, ok := object.(*types.Func)
	if !ok {
		return nil
	}
	return function
}

func isTestingRun(expression ast.Expr, info *types.Info) bool {
	runCall, ok := expression.(*ast.CallExpr)
	if !ok || len(runCall.Args) != 0 {
		return false
	}
	run, ok := runCall.Fun.(*ast.SelectorExpr)
	return ok && isTestingMRun(info.Uses[run.Sel])
}

func isTestingMRun(object types.Object) bool {
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil ||
		function.Pkg().Path() != "testing" ||
		function.Name() != "Run" {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return false
	}
	pointer, ok := signature.Recv().Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "testing" &&
		named.Obj().Name() == "M"
}
