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
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"
)

func nonzeroExitCode(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return false
	}
	value, err := strconv.ParseInt(literal.Value, 0, 64)
	return err == nil && value != 0
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
	object := expressionFunction(expression, info)
	if object == nil || object.Pkg() == nil {
		return false
	}
	if object.Pkg().Path() == "github.com/sirupsen/logrus" &&
		object.Name() == "Exit" {
		return true
	}
	switch object.Name() {
	case "Exit", "ExitProcess", "ProcExit", "TerminateProcess":
	default:
		return false
	}
	return isSystemPackage(object.Pkg().Path())
}

func isRawSyscallFunction(expression ast.Expr, info *types.Info) bool {
	object := expressionFunction(expression, info)
	if object == nil || object.Pkg() == nil {
		return false
	}
	name := object.Name()
	if !strings.HasPrefix(name, "Syscall") &&
		!strings.HasPrefix(name, "RawSyscall") &&
		!strings.HasPrefix(name, "AllThreadsSyscall") {
		return false
	}
	return isSystemPackage(object.Pkg().Path())
}

func isSuccessfulTerminateProcessCall(
	call *ast.CallExpr,
	info *types.Info,
) bool {
	return isTerminateProcessCall(call, info) &&
		(len(call.Args) != 2 || !provenNonzeroInteger(call.Args[1], info))
}

func isTerminateProcessCall(call *ast.CallExpr, info *types.Info) bool {
	return isSystemFunction(call.Fun, "TerminateProcess", info)
}

func isDynamicProcessExitResolution(
	call *ast.CallExpr,
	info *types.Info,
) bool {
	if len(call.Args) == 0 {
		return false
	}
	function := expressionFunction(call.Fun, info)
	if function == nil || !isProcessResolverFunction(call.Fun, info) {
		return false
	}
	value := info.Types[call.Args[len(call.Args)-1]].Value
	return value == nil ||
		value.Kind() != constant.String ||
		constant.StringVal(value) == "ExitProcess" ||
		constant.StringVal(value) == "TerminateProcess"
}

func isProcessResolverFunction(expression ast.Expr, info *types.Info) bool {
	function := expressionFunction(expression, info)
	if function == nil || function.Pkg() == nil {
		return false
	}
	switch function.Name() {
	case "NewProc", "FindProc", "MustFindProc":
		return isSystemPackage(function.Pkg().Path())
	default:
		return false
	}
}

func isSystemFunction(
	expression ast.Expr,
	name string,
	info *types.Info,
) bool {
	object := functionObject(expression, name, info)
	return object != nil && object.Pkg() != nil &&
		isSystemPackage(object.Pkg().Path())
}

func provenNonzeroInteger(expression ast.Expr, info *types.Info) bool {
	value := info.Types[expression].Value
	return value != nil && value.Kind() == constant.Int &&
		constant.Sign(value) != 0
}

func isSystemPackage(path string) bool {
	switch path {
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
