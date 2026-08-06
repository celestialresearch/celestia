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
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

const clone3HelperArgument = "clone3-gate-helper"

func TestClone3CgroupHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != clone3HelperArgument {
		return
	}
	gate := os.NewFile(uintptr(4), "clone3-gate")
	ready := os.NewFile(uintptr(3), "clone3-ready")
	if err := runClone3Bootstrap(gate, ready, func() error { return nil }); err != nil {
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
	command := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestClone3CgroupHelper$", "--", clone3HelperArgument)
	return command
}
