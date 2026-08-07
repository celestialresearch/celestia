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

//go:build linux && amd64

package linuxamd64feasibility

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const clone3BootstrapHelperArgument = "clone3-bootstrap-helper"

const clone3CoverageMarker = "clone3 coverage flushed"

func TestClone3BootstrapHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != clone3BootstrapHelperArgument {
		return
	}
	gate := os.NewFile(4, "clone3-gate")
	ready := os.NewFile(3, "clone3-ready")
	fixture := os.NewFile(5, "hostile-fixture")
	if err := Bootstrap(gate, ready, fixture); err != nil {
		written, coverageErr := writeClone3Coverage()
		if coverageErr != nil {
			t.Fatalf("write coverage: %v; bootstrap: %v", coverageErr, err)
		}
		if written {
			if _, markerErr := fmt.Fprintln(os.Stderr, clone3CoverageMarker); markerErr != nil {
				t.Fatalf("write coverage marker: %v", markerErr)
			}
		}
		t.Fatalf("bootstrap: %v", err)
	}
	t.Fatal("bootstrap returned without executing fixture")
}

func TestClone3CgroupPrimitiveNative(t *testing.T) {
	root := os.Getenv("CELESTIA_CGROUP_ROOT")
	if root == "" {
		return
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	command := clone3TestCommand(t)
	result := clone3CgroupPrimitive(root, command, file)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v stderr=%q", result, command.Stderr)
	}
}

func TestClone3BootstrapNative(t *testing.T) {
	root := os.Getenv("CELESTIA_CGROUP_ROOT")
	if root == "" {
		return
	}
	fixtureRoot := t.TempDir()
	fixtureName := "fixture"
	writeStaticTestExecutable(t, filepath.Join(fixtureRoot, fixtureName))
	fixture, _, err := openStaticFixture(fixtureRoot, fixtureName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	command := clone3HelperCommand(t, "^TestClone3BootstrapHelper$", clone3BootstrapHelperArgument)
	result := clone3CgroupPrimitive(root, command, fixture)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
}

func TestClone3BootstrapFailureNative(t *testing.T) {
	root := os.Getenv("CELESTIA_CGROUP_ROOT")
	if root == "" {
		return
	}
	fixture, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	command := clone3CoverageHelperCommand(t, "^TestClone3BootstrapHelper$", clone3BootstrapHelperArgument)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	result := clone3CgroupPrimitive(root, command, fixture)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
	if os.Getenv("GOCOVERDIR") != "" && !bytes.Contains(stderr.Bytes(), []byte(clone3CoverageMarker)) {
		t.Fatalf("coverage marker missing: %q", stderr.String())
	}
}
