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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const clone3BootstrapHelperArgument = "clone3-bootstrap-helper"

func TestClone3BootstrapHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != clone3BootstrapHelperArgument {
		return
	}
	gate := os.NewFile(4, "clone3-gate")
	ready := os.NewFile(3, "clone3-ready")
	fixture := os.NewFile(5, "hostile-fixture")
	if err := Bootstrap(gate, ready, fixture); err != nil {
		os.Exit(4)
	}
	os.Exit(5)
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
	result := clone3CgroupPrimitive(root, clone3TestCommand(t), file)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v", result)
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
	command := exec.CommandContext(t.Context(), "/proc/self/exe",
		"-test.run=^TestClone3BootstrapHelper$", "--", clone3BootstrapHelperArgument)
	result := clone3CgroupPrimitive(root, command, fixture)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
}
