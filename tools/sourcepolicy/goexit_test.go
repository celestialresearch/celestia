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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoPolicyRejectsTestMainBypasses(t *testing.T) {
	tests := map[string]string{
		"function literal": "go func() { os.Exit(0) }()\n",
		"repeated run":     "_ = m.Run()\n",
	}
	for name, statement := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			mainPath := filepath.Join(root, "main.go")
			testPath := filepath.Join(root, "main_test.go")
			writeGoPolicyFixture(t, root, map[string]string{
				mainPath: "package main\n\nfunc main() {}\n",
				testPath: "package main\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n" +
					"func TestMain(m *testing.M) {\n" + statement +
					"\tos.Exit(m.Run())\n}\n",
			})
			t.Chdir(root)
			findings, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Base(mainPath), filepath.Base(testPath)},
				os.ReadFile,
				[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 ||
				!strings.Contains(findings[0], "TestMain violates") {
				t.Fatalf("findings = %v, want TestMain finding", findings)
			}
		})
	}
}

func TestGoPolicyRecognisesSystemExit(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"golang.org/x/sys/windows",
		"golang.org/x/sys/unix",
		"golang.org/x/sys/plan9",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			pkg := types.NewPackage(path, filepath.Base(path))
			signature := types.NewSignatureType(
				nil,
				nil,
				nil,
				types.NewTuple(types.NewParam(
					token.NoPos, pkg, "code", types.Typ[types.Int],
				)),
				nil,
				false,
			)
			function := types.NewFunc(token.NoPos, pkg, "Exit", signature)
			identifier := &ast.Ident{Name: "Exit"}
			info := &types.Info{
				Uses: map[*ast.Ident]types.Object{identifier: function},
			}
			if !isProcessExitFunction(identifier, info) {
				t.Fatalf("%s Exit was not recognised", path)
			}
		})
	}
}

func TestGoPolicyRecognisesRawSyscalls(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"syscall": {
			"Syscall",
			"Syscall6",
			"RawSyscall",
			"AllThreadsSyscall",
			"AllThreadsSyscall6",
		},
		"golang.org/x/sys/unix":  {"Syscall", "RawSyscall"},
		"golang.org/x/sys/plan9": {"Syscall", "RawSyscall"},
	}
	for path, names := range tests {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			pkg := types.NewPackage(path, filepath.Base(path))
			for _, name := range names {
				function := types.NewFunc(
					token.NoPos,
					pkg,
					name,
					types.NewSignatureType(nil, nil, nil, nil, nil, false),
				)
				identifier := &ast.Ident{Name: name}
				info := &types.Info{
					Uses: map[*ast.Ident]types.Object{identifier: function},
				}
				if !isRawSyscallFunction(identifier, info) {
					t.Fatalf("%s.%s was not recognised", path, name)
				}
			}
		})
	}
}

func TestGoPolicyRecognisesWindowsTermination(t *testing.T) {
	t.Parallel()
	windows := types.NewPackage("golang.org/x/sys/windows", "windows")
	terminate := testFunction(windows, "TerminateProcess")
	newProc := testFunction(windows, "NewProc")
	mustFindProc := testFunction(windows, "MustFindProc")
	terminateIdentifier := &ast.Ident{Name: "TerminateProcess"}
	newProcIdentifier := &ast.Ident{Name: "NewProc"}
	mustFindProcIdentifier := &ast.Ident{Name: "MustFindProc"}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses: map[*ast.Ident]types.Object{
			terminateIdentifier:    terminate,
			newProcIdentifier:      newProc,
			mustFindProcIdentifier: mustFindProc,
		},
	}
	zero := &ast.BasicLit{Kind: token.INT, Value: "0"}
	info.Types[zero] = types.TypeAndValue{
		Type:  types.Typ[types.UntypedInt],
		Value: constant.MakeInt64(0),
	}
	terminateCall := &ast.CallExpr{
		Fun: terminateIdentifier,
		Args: []ast.Expr{
			&ast.Ident{Name: "process"},
			zero,
		},
	}
	if !isSuccessfulTerminateProcessCall(terminateCall, info) {
		t.Fatal("TerminateProcess(process, 0) was not recognised")
	}

	exitName := &ast.BasicLit{Kind: token.STRING, Value: `"ExitProcess"`}
	info.Types[exitName] = types.TypeAndValue{
		Type:  types.Typ[types.UntypedString],
		Value: constant.MakeString("ExitProcess"),
	}
	if !isDynamicProcessExitResolution(&ast.CallExpr{
		Fun: newProcIdentifier,
		Args: []ast.Expr{
			&ast.Ident{Name: "dll"},
			exitName,
		},
	}, info) {
		t.Fatal(`LazyDLL.NewProc(dll, "ExitProcess") was not recognised`)
	}
	terminateName := &ast.BasicLit{
		Kind:  token.STRING,
		Value: `"TerminateProcess"`,
	}
	info.Types[terminateName] = types.TypeAndValue{
		Type:  types.Typ[types.UntypedString],
		Value: constant.MakeString("TerminateProcess"),
	}
	if !isDynamicProcessExitResolution(&ast.CallExpr{
		Fun:  mustFindProcIdentifier,
		Args: []ast.Expr{terminateName},
	}, info) {
		t.Fatal(`MustFindProc("TerminateProcess") was not recognised`)
	}
}

func testFunction(pkg *types.Package, name string) *types.Func {
	return types.NewFunc(
		token.NoPos,
		pkg,
		name,
		types.NewSignatureType(nil, nil, nil, nil, nil, false),
	)
}

func TestGoPolicyRecognisesProcessTermination(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"syscall": {
			"Exit",
			"ExitProcess",
			"ProcExit",
			"TerminateProcess",
		},
		"golang.org/x/sys/windows": {
			"Exit",
			"ExitProcess",
			"TerminateProcess",
		},
		"golang.org/x/sys/unix":  {"Exit"},
		"golang.org/x/sys/plan9": {"Exit"},
	}
	for path, names := range tests {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			pkg := types.NewPackage(path, filepath.Base(path))
			for _, name := range names {
				function := types.NewFunc(
					token.NoPos,
					pkg,
					name,
					types.NewSignatureType(nil, nil, nil, nil, nil, false),
				)
				identifier := &ast.Ident{Name: name}
				info := &types.Info{
					Uses: map[*ast.Ident]types.Object{identifier: function},
				}
				if !isProcessExitFunction(identifier, info) {
					t.Fatalf("%s.%s was not recognised", path, name)
				}
			}
		})
	}
}
