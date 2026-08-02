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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoSuccessfulExit(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		message string
	}{
		{
			"qualified",
			"import (\"os\"; \"testing\")\n" +
				"func init() { os.Exit(0) }\n" +
				"func fail() { os.Exit(2) }\n",
			"Go tests must not exit successfully",
		},
		{
			"dot imported",
			"import (. \"os\"; \"testing\")\n" +
				"func init() { Exit(0) }\n",
			"Go tests must not exit successfully",
		},
		{
			"syscall",
			"import (\"syscall\"; \"testing\")\n" +
				"func init() { syscall.Exit(0) }\n",
			"Go tests must not exit successfully",
		},
		{
			"aliased function",
			"import (\"os\"; \"testing\")\n" +
				"var exit = os.Exit\n" +
				"func init() { exit(0) }\n",
			"Go tests must not alias process exit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "exit_test.go")
			writeGoPolicyFixture(t, root, map[string]string{
				path: "package fixture\n\n" + test.source +
					"func TestFailure(t *testing.T) { t.Fatal(\"must run\") }\n",
			})
			t.Chdir(root)
			findings, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Base(path)},
				os.ReadFile,
				[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 ||
				!strings.Contains(findings[0], test.message) {
				t.Fatalf("findings = %v, want one %s", findings, test.message)
			}
		})
	}
}

func TestGoTestCannotInvokeMain(t *testing.T) {
	tests := []struct {
		name string
		main string
		test string
	}{
		{
			"direct",
			"func main() {}\n",
			"func TestEntry(t *testing.T) { main() }\n",
		},
		{
			"aliased",
			"func main() {}\n",
			"func TestEntry(t *testing.T) { entry := main; entry() }\n",
		},
		{
			"wrapped",
			"func main() {}\nfunc invokeMain() { main() }\n",
			"func TestEntry(t *testing.T) { invokeMain() }\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			mainPath := filepath.Join(root, "main.go")
			testPath := filepath.Join(root, "main_test.go")
			writeGoPolicyFixture(t, root, map[string]string{
				mainPath: "package main\n\n" + test.main,
				testPath: "package main\n\nimport \"testing\"\n\n" + test.test,
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
			if len(findings) == 0 ||
				!strings.Contains(findings[0], "executable main") {
				t.Fatalf("findings = %v, want executable main finding", findings)
			}
		})
	}
}

func TestValidTestMainSyntax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		body  string
		valid bool
	}{
		{"exit run", "os.Exit(testingMain.Run())", true},
		{
			"setup then exit",
			"fmt.Println(\"setup\"); os.Exit(testingMain.Run())",
			true,
		},
		{
			"closure return",
			"func() { return }(); os.Exit(testingMain.Run())",
			true,
		},
		{
			"non-zero early exit",
			"os.Exit(2); os.Exit(testingMain.Run())",
			true,
		},
		{
			"custom exit field",
			"customExit.Exit(2); os.Exit(testingMain.Run())",
			true,
		},
		{"empty", "", false},
		{"return", "return", false},
		{
			"early return",
			"if true { return }; os.Exit(testingMain.Run())",
			false,
		},
		{"successful early exit", "os.Exit(0); os.Exit(testingMain.Run())", false},
		{"bare run", "testingMain.Run()", false},
		{"other exit", "fmt.Println(testingMain.Run())", false},
		{"missing argument", "os.Exit()", false},
		{"constant exit", "os.Exit(0)", false},
		{"run argument", "os.Exit(testingMain.Run(1))", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			files := token.NewFileSet()
			source := "package fixture\n" +
				"import (\"fmt\"; \"os\"; \"testing\")\n" +
				"type exits struct { Exit func(int) }\n" +
				"var customExit exits\n" +
				"func TestMain(testingMain *testing.M) {" + test.body + "}\n"
			file, err := parser.ParseFile(files, "fixture_test.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			info := goTypeInfo([]*ast.File{file}, files)
			function, ok := file.Decls[3].(*ast.FuncDecl)
			if !ok {
				t.Fatal("TestMain declaration is not a function")
			}
			if valid := validTestMainSyntax(function, info); valid != test.valid {
				t.Fatalf("valid = %t, want %t", valid, test.valid)
			}
			if !isTestingMain(function, info) {
				t.Fatal("testing TestMain signature rejected")
			}
		})
	}
}
