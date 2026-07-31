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
	"context"
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

func TestReadSourceFailures(t *testing.T) {
	rootPath := t.TempDir()
	filePath := filepath.Join(rootPath, "source.go")
	if err := os.WriteFile(filePath, []byte("package source"), 0o600); err != nil {
		t.Fatal(err)
	}
	openRoot := func(string) (*os.Root, error) {
		return os.OpenRoot(rootPath)
	}
	openFile := func(root *os.Root, name string) (*os.File, error) {
		return root.Open(name)
	}
	statPath := func(root *os.Root, name string) (os.FileInfo, error) {
		return root.Stat(name)
	}
	realStat := func(file *os.File) (os.FileInfo, error) {
		return file.Stat()
	}
	failure := errors.New("injected failure")
	tests := []struct {
		name   string
		reader sourceReader
	}{
		{
			name: "open root",
			reader: sourceReader{
				openRoot: func(string) (*os.Root, error) { return nil, failure },
			},
		},
		{
			name: "open file",
			reader: sourceReader{
				openRoot: openRoot,
				statPath: statPath,
				openFile: func(*os.Root, string) (*os.File, error) {
					return nil, failure
				},
			},
		},
		{
			name: "stat path",
			reader: sourceReader{
				openRoot: openRoot,
				statPath: func(*os.Root, string) (os.FileInfo, error) {
					return nil, failure
				},
			},
		},
		{
			name: "stat",
			reader: sourceReader{
				openRoot: openRoot,
				statPath: statPath,
				openFile: openFile,
				stat: func(*os.File) (os.FileInfo, error) {
					return nil, failure
				},
			},
		},
		{
			name: "read",
			reader: sourceReader{
				openRoot: openRoot,
				statPath: statPath,
				openFile: openFile,
				stat:     realStat,
				read: func(io.Reader) ([]byte, error) {
					return nil, failure
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readSourceWith("source.go", test.reader)
			if !errors.Is(err, failure) {
				t.Fatalf("readSourceWith error = %v, want %v", err, failure)
			}
		})
	}
}

func TestReadSourcePostOpenType(t *testing.T) {
	rootPath := t.TempDir()
	filePath := filepath.Join(rootPath, "source.go")
	if err := os.WriteFile(filePath, []byte("package source"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	read := false
	_, err = readSourceWith("source.go", sourceReader{
		openRoot: func(string) (*os.Root, error) {
			return os.OpenRoot(rootPath)
		},
		statPath: (*os.Root).Stat,
		openFile: func(root *os.Root, name string) (*os.File, error) {
			return root.Open(name)
		},
		stat: func(*os.File) (os.FileInfo, error) {
			return directory, nil
		},
		read: func(io.Reader) ([]byte, error) {
			read = true
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("post-open type error = %v", err)
	}
	if read {
		t.Fatal("post-open non-regular source was read")
	}
}

func TestReadSourceGrowth(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(rootPath, "source.go"),
		[]byte("package source"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	source, err := readSourceWith("source.go", sourceReader{
		openRoot: func(string) (*os.Root, error) {
			return os.OpenRoot(rootPath)
		},
		statPath: (*os.Root).Stat,
		openFile: func(root *os.Root, name string) (*os.File, error) {
			return root.Open(name)
		},
		stat: (*os.File).Stat,
		read: func(io.Reader) ([]byte, error) {
			return bytes.Repeat([]byte{'x'}, maxSourceBytes+1), nil
		},
	})
	if err == nil || source != nil ||
		!strings.Contains(err.Error(), "source file exceeds") {
		t.Fatalf("grown source = %d bytes, %v", len(source), err)
	}
}

func TestGoSkipLoadFailures(t *testing.T) {
	target := buildTarget{goos: "linux", goarch: "amd64"}
	loadErr := errors.New("load failed")
	_, err := goSkipFindingsForTargetWith(
		context.Background(),
		target,
		[]string{"./..."},
		func(*packages.Config, ...string) ([]*packages.Package, error) {
			return nil, loadErr
		},
	)
	if !errors.Is(err, loadErr) {
		t.Fatalf("load error = %v, want %v", err, loadErr)
	}

	_, err = goSkipFindingsForTargetWith(
		context.Background(),
		target,
		[]string{"./..."},
		func(*packages.Config, ...string) ([]*packages.Package, error) {
			return []*packages.Package{{
				Errors: []packages.Error{{Msg: "package failed"}},
			}}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "package failed") {
		t.Fatalf("package error = %v", err)
	}

	_, err = goSkipFindingsForTargetWith(
		context.Background(),
		buildTarget{goos: "linux", goarch: "amd64", cgo: true},
		[]string{"./..."},
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			for _, value := range []string{
				"GOOS=linux",
				"GOARCH=amd64",
				"CGO_ENABLED=1",
				"GOAMD64=v1",
				"GOENV=off",
				"GOFLAGS=",
				"GOPACKAGESDRIVER=off",
				"GOTOOLCHAIN=local",
				"GOWORK=off",
			} {
				if !slices.Contains(config.Env, value) {
					t.Errorf("environment omits %q", value)
				}
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("CGO load error = %v", err)
	}
}

func TestGoRaceLoadFlags(t *testing.T) {
	_, err := goSkipFindingsForTargetWith(
		context.Background(),
		buildTarget{
			goos: "linux", goarch: "amd64", cgo: true, race: true,
		},
		[]string{"./..."},
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			if !slices.Equal(config.BuildFlags, []string{"-tags=race"}) {
				t.Errorf("build flags = %v, want race tag", config.BuildFlags)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("race load error = %v", err)
	}
}

func TestGoLoadDisablesPackageDriver(t *testing.T) {
	t.Setenv("GOPACKAGESDRIVER", "untrusted-driver")
	root := t.TempDir()
	testPath := filepath.Join(root, "driver_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"func TestDriver(t *testing.T) { t.Skip(\"hidden\") }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want one skip", findings)
	}
}

func TestGoPolicyUsesPhysicalPositions(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "main.go")
	testPath := filepath.Join(root, "main_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		mainPath: "package main\n\nfunc main() {}\n",
		testPath: "package main\n\nimport \"testing\"\n\n" +
			"//line ordinary.go:1\n" +
			"func TestMain(m *testing.M) { return }\n",
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
		!strings.Contains(findings[0], "TestMain violates") ||
		!strings.Contains(findings[0], "main_test.go") {
		t.Fatalf("findings = %v, want physical TestMain finding", findings)
	}
}

func TestGoPolicyRejectsNativeSource(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "native_test.go")
	nativePath := filepath.Join(root, "call_amd64.s")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"func TestNative(t *testing.T) {}\n",
		nativePath: "TEXT ·entry(SB),$0-0\n\tRET\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath), filepath.Base(nativePath)},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err == nil || !strings.Contains(err.Error(), "native source") {
		t.Fatalf("native-source error = %v", err)
	}
}

func TestGoPolicyIgnoresUnrelatedNativeSource(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "fixture", "ordinary_test.go")
	nativePath := filepath.Join(root, "other", "ordinary.h")
	if err := os.MkdirAll(filepath.Dir(testPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(nativePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"func TestOrdinary(t *testing.T) {}\n",
		nativePath: "#define ORDINARY 1\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{
			filepath.Join("fixture", "ordinary_test.go"),
			filepath.Join("other", "ordinary.h"),
		},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGoPolicyRejectsArchitectureFeatures(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "feature_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "//go:build amd64.v2\n\npackage fixture\n\n" +
			"import \"testing\"\n\nfunc TestFeature(t *testing.T) {}\n",
	})
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: "linux", goarch: "amd64"}},
	)
	if err == nil ||
		!strings.Contains(err.Error(), "architecture feature build constraints") {
		t.Fatalf("architecture-feature error = %v", err)
	}
}

func TestGoPolicyRejectsExternalReplacement(t *testing.T) {
	root := t.TempDir()
	modulePath := filepath.Join(root, "go.mod")
	testPath := filepath.Join(root, "replace_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport \"testing\"\n\n" +
			"func TestReplacement(t *testing.T) {}\n",
	})
	if err := os.WriteFile(
		modulePath,
		[]byte("module fixture.invalid/root\n\ngo 1.26.5\n\n"+
			"replace fixture.invalid/helper => ../helper\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	_, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(modulePath), filepath.Base(testPath)},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err == nil || !strings.Contains(err.Error(), "escapes the repository") {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestGoPolicyRejectsLinkedReplacement(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink(external, link); err != nil {
		t.Fatalf("create replacement link: %v", err)
	}
	modulePath := filepath.Join(root, "go.mod")
	module, err := modfile.Parse(
		modulePath,
		[]byte("module fixture.invalid/root\n\ngo 1.26.5\n\n"+
			"replace fixture.invalid/helper => ./linked\n"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	escapes, err := moduleReplacementEscapes(
		modulePath,
		module.Replace[0],
		root,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !escapes {
		t.Fatal("linked replacement outside repository was accepted")
	}
}

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
	for _, path := range []string{
		"syscall",
		"golang.org/x/sys/windows",
		"golang.org/x/sys/unix",
		"golang.org/x/sys/plan9",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			pkg := types.NewPackage(path, filepath.Base(path))
			for _, name := range []string{"Syscall", "Syscall6", "RawSyscall"} {
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

func TestGoLoadUsesSourceOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.go")
	source := []byte("package helper\n")
	overlay := map[string][]byte{path: source}
	_, err := goSkipFindingsForTargetWithOverlay(
		context.Background(),
		buildTarget{goos: "linux", goarch: "amd64"},
		[]string{"./..."},
		overlay,
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			if !bytes.Equal(config.Overlay[path], source) {
				t.Errorf("source overlay = %q, want %q", config.Overlay[path], source)
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("overlay load error = %v", err)
	}
}

func TestGoBuildUnitsPropagateCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runGoBuildUnitsWith(
		ctx,
		[]goBuildUnit{{
			target:   buildTarget{goos: "linux", goarch: "amd64"},
			patterns: []string{"./..."},
		}},
		func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
			if config.Context != ctx {
				t.Fatal("package loader received a different context")
			}
			return nil, config.Context.Err()
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("load error = %v, want context cancellation", err)
	}
}
