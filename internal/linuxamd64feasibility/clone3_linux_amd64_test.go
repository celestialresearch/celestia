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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const clone3HelperArgument = "clone3-gate-helper"

func TestClone3CgroupHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != clone3HelperArgument {
		return
	}
	gate := os.NewFile(uintptr(4), "clone3-gate")
	ready := os.NewFile(uintptr(3), "clone3-ready")
	if err := runClone3Bootstrap(gate, ready, func() error { return nil }); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	os.Exit(5)
}

func TestClone3GateRequiresRelease(t *testing.T) {
	pipes, err := newClone3Pipes()
	if err != nil {
		t.Fatalf("create pipes: %v", err)
	}
	defer func() {
		if err := pipes.closeParentEnds(); err != nil {
			t.Errorf("close parent pipes: %v", err)
		}
	}()
	command := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestClone3CgroupHelper$", "--", clone3HelperArgument)
	command.ExtraFiles = []*os.File{pipes.readyWrite, pipes.gateRead}
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	if err := pipes.closeChildEnds(); err != nil {
		t.Fatalf("close child pipes: %v", err)
	}
	if err := pipes.readyEmpty(); err != nil {
		t.Fatalf("helper bypassed gate: %v", err)
	}
	if err := pipes.release(); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	if err := pipes.waitReady(time.Now().Add(clone3ProbeTimeout)); err != nil {
		t.Fatalf("helper ready: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	if !waitClone3Command(command) {
		t.Fatal("wait helper failed")
	}
}

func TestClone3StartRejectsCallerOwnedProcessState(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open null: %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close null: %v", err)
		}
	})
	cases := map[string]*exec.Cmd{
		"nil":         nil,
		"empty path":  {},
		"extra files": {Path: "/proc/self/exe", ExtraFiles: []*os.File{file}},
		"attributes":  {Path: "/proc/self/exe", SysProcAttr: &syscall.SysProcAttr{}},
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			child, err := startClone3Child(ownedCgroupLeaf{}, command, file)
			if child != nil || !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("child=%v err=%v", child, err)
			}
		})
	}
}

func TestClone3StartResultDistinguishesPlacementDenial(t *testing.T) {
	if result := clone3StartResult(unix.EACCES); result.Reason != "clone3_placement_denied" {
		t.Fatalf("result = %+v", result)
	}
}

func TestClone3FailureResults(t *testing.T) {
	unknown := errors.New("unknown failure")
	tests := map[string]struct {
		result cgroupResult
		want   cgroupResult
	}{
		"limit unavailable": {clone3LimitResult(unix.EPERM),
			unavailableCgroup("clone3_process_limit_unavailable")},
		"limit indeterminate": {clone3LimitResult(unknown),
			indeterminateCgroup("clone3_process_limit_indeterminate")},
		"start unavailable":   {clone3StartResult(unix.ENOSYS), unavailableCgroup("clone3_unavailable")},
		"start indeterminate": {clone3StartResult(unknown), indeterminateCgroup("clone3_start_indeterminate")},
		"membership unavailable": {clone3MembershipResult(unix.EACCES),
			unavailableCgroup("clone3_membership_unavailable")},
		"membership indeterminate": {clone3MembershipResult(unknown),
			indeterminateCgroup("clone3_membership_indeterminate")},
		"freeze unavailable": {clone3FreezeResult(errCgroupDeadlineExceeded),
			unavailableCgroup("cgroup_freeze_unavailable")},
		"freeze indeterminate": {clone3FreezeResult(unknown),
			indeterminateCgroup("cgroup_freeze_indeterminate")},
		"ready unavailable":   {clone3ReadyResult(unix.EPIPE), unavailableCgroup("clone3_gate_unavailable")},
		"ready indeterminate": {clone3ReadyResult(unknown), indeterminateCgroup("clone3_gate_indeterminate")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.result != test.want {
				t.Fatalf("result=%+v want=%+v", test.result, test.want)
			}
		})
	}
}

func TestClone3CgroupPrimitiveRefusesOrdinaryRoot(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	result := clone3CgroupPrimitive(t.TempDir(), clone3TestCommand(t), file)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "unavailable" || result.Reason != "cgroup_v2_missing" {
		t.Fatalf("result=%+v", result)
	}
}

func clone3TestCommand(t *testing.T) *exec.Cmd {
	t.Helper()
	command := clone3HelperCommand(t, "^TestClone3CgroupHelper$", clone3HelperArgument)
	command.Stderr = &nativeFixtureOutput{}
	return command
}

func clone3HelperCommand(t *testing.T, testName, argument string) *exec.Cmd {
	t.Helper()
	arguments := []string{"-test.run=" + testName}
	command := exec.CommandContext(t.Context(), "/proc/self/exe")
	if attachClone3Coverage(t, command) {
		arguments = append(arguments, "-test.gocoverdir=/proc/self/fd/0")
	}
	command.Args = append(command.Args, append(arguments, "--", argument)...)
	return command
}

func attachClone3Coverage(t *testing.T, command *exec.Cmd) bool {
	t.Helper()
	path := os.Getenv("GOCOVERDIR")
	if path == "" {
		return false
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatalf("open coverage directory: %v", err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close coverage directory: %v", err)
		}
	})
	command.Stdin = directory
	return true
}
