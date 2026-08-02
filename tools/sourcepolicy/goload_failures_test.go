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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

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

func TestGoPolicyRejectsModuleReplacement(t *testing.T) {
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
			"replace fixture.invalid/helper => ./helper\n"),
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
	if err == nil || !strings.Contains(err.Error(), "replacements are prohibited") {
		t.Fatalf("replacement error = %v", err)
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
	called := make(chan struct{}, 1)
	_, err := runGoBuildUnitsWith(
		ctx,
		[]goBuildUnit{{
			target:   buildTarget{goos: "linux", goarch: "amd64"},
			patterns: []string{"./..."},
		}},
		func(*packages.Config, ...string) ([]*packages.Package, error) {
			called <- struct{}{}
			return nil, nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("load error = %v, want context cancellation", err)
	}
	select {
	case <-called:
		t.Fatal("package load started after cancellation")
	default:
	}
}
