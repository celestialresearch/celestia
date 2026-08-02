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
	"go/ast"
	"go/types"
	"strings"
)

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
