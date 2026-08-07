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
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	clone3BootstrapHelperArgument   = "clone3-bootstrap-helper"
	clone3BootstrapCoverageArgument = "clone3-bootstrap-coverage-helper"
	clone3PreparationHelperArgument = "clone3-preparation-helper"
)

const clone3CoverageMarker = "clone3 coverage flushed"

func TestClone3BootstrapHelper(t *testing.T) {
	if len(os.Args) == 0 {
		return
	}
	if os.Args[len(os.Args)-1] == clone3PreparationHelperArgument {
		runClone3PreparationHelper(t)
		return
	}
	argument := os.Args[len(os.Args)-1]
	if argument != clone3BootstrapHelperArgument && argument != clone3BootstrapCoverageArgument {
		return
	}
	gate := os.NewFile(4, "clone3-gate")
	ready := os.NewFile(3, "clone3-ready")
	fixture := os.NewFile(5, "hostile-fixture")
	if err := Bootstrap(gate, ready, fixture); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	t.Fatal("bootstrap returned without executing fixture")
}

func runClone3PreparationHelper(t *testing.T) {
	t.Helper()
	if err := prepareClone3Namespace(); err != nil {
		t.Fatalf("prepare namespace: %v", err)
	}
	if _, err := fmt.Fprintln(os.Stderr, clone3CoverageMarker); err != nil {
		t.Fatalf("write coverage marker: %v", err)
	}
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

func TestClone3PreparationCoverageNative(t *testing.T) {
	root := os.Getenv("CELESTIA_CGROUP_ROOT")
	if root == "" {
		return
	}
	command := clone3CoverageHelperCommand(t, "^TestClone3BootstrapHelper$", clone3PreparationHelperArgument)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	result := clone3PreparationCoverage(root, command)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v output=%q", result, output.String())
	}
	if os.Getenv("GOCOVERDIR") != "" && !bytes.Contains(output.Bytes(), []byte(clone3CoverageMarker)) {
		t.Fatalf("coverage marker missing: %q", output.String())
	}
}

func TestClone3BootstrapCoverageNative(t *testing.T) {
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
	command := clone3CoverageHelperCommand(t, "^TestClone3BootstrapHelper$", clone3BootstrapCoverageArgument)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	result := clone3BootstrapCoverage(root, command, fixture)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v output=%q", result, output.String())
	}
}

func clone3PreparationCoverage(root string, command *exec.Cmd) (result cgroupResult) {
	directory, err := openCgroupDirectory(root)
	if err != nil {
		return cgroupOpenResult(err)
	}
	defer func() {
		result = finishCgroupCleanup(result, directory.close())
	}()
	if result = validateDelegatedCgroup(directory); result.Outcome != "passed" {
		return result
	}
	return useCgroupLeaf(directory, func(leaf ownedCgroupLeaf) cgroupResult {
		if err := leaf.write("pids.max", []byte(clone3BootstrapTaskLimit)); err != nil {
			return clone3LimitResult(err)
		}
		if err := configureClone3Namespaces(command, leaf); err != nil {
			return clone3StartResult(err)
		}
		if err := command.Run(); err != nil {
			return clone3StartResult(err)
		}
		return cgroupResult{Outcome: "passed", Reason: "clone3_namespace_prepared"}
	})
}

func clone3BootstrapCoverage(root string, command *exec.Cmd, fixture *os.File) (result cgroupResult) {
	directory, err := openCgroupDirectory(root)
	if err != nil {
		return cgroupOpenResult(err)
	}
	defer func() {
		result = finishCgroupCleanup(result, directory.close())
	}()
	if result = validateDelegatedCgroup(directory); result.Outcome != "passed" {
		return result
	}
	return useCgroupLeaf(directory, func(leaf ownedCgroupLeaf) cgroupResult {
		return runBootstrapCoverageLeaf(leaf, command, fixture)
	})
}

func runBootstrapCoverageLeaf(leaf ownedCgroupLeaf, command *exec.Cmd, fixture *os.File) cgroupResult {
	deadline := time.Now().Add(clone3ProbeTimeout)
	if err := leaf.write("pids.max", []byte(clone3BootstrapTaskLimit)); err != nil {
		return clone3LimitResult(err)
	}
	child, err := startClone3Child(leaf, command, fixture)
	if child == nil {
		return clone3StartResult(err)
	}
	if err != nil {
		return cleanupClone3Child(clone3StartResult(err), leaf, child, deadline)
	}
	if err := child.pipes.release(); err != nil {
		return cleanupClone3Child(indeterminateCgroup("clone3_gate_release_failed"), leaf, child, deadline)
	}
	if err := child.pipes.waitReady(deadline); err != nil {
		return cleanupClone3Child(clone3ReadyResult(err), leaf, child, deadline)
	}
	if err := child.pipes.release(); err != nil {
		return cleanupClone3Child(indeterminateCgroup("clone3_gate_release_failed"), leaf, child, deadline)
	}
	if !child.reap(deadline) {
		return cleanupClone3Child(indeterminateCgroup("clone3_gate_indeterminate"), leaf, child, deadline)
	}
	complete := child.close() == nil && leaf.waitEmpty(deadline) == nil
	return cgroupResult{Outcome: "passed", Reason: "clone3_bootstrap_covered", CleanupAttempted: true, CleanupComplete: complete}
}
