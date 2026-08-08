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
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

func TestClone3PipeProtocolFailures(t *testing.T) {
	pipes, err := newClone3Pipes()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := errors.Join(pipes.closeChildEnds(), pipes.closeParentEnds()); err != nil {
			t.Errorf("close pipes: %v", err)
		}
	}()
	if _, err := pipes.readyWrite.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if err := pipes.readyEmpty(); !errors.Is(err, errCgroupEventsMalformed) {
		t.Fatalf("unexpected ready byte: %v", err)
	}
	if _, err := pipes.readyWrite.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if err := pipes.waitReady(time.Now().Add(time.Second)); !errors.Is(err, errCgroupEventsMalformed) {
		t.Fatalf("unexpected wait byte: %v", err)
	}
	if err := pipes.waitReady(time.Now().Add(-time.Second)); !errors.Is(err, errCgroupDeadlineExceeded) {
		t.Fatalf("expired wait: %v", err)
	}
}

func TestClone3PipeDescriptorFailures(t *testing.T) {
	pipes, err := newClone3Pipes()
	if err != nil {
		t.Fatal(err)
	}
	if err := pipes.readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pipes.readyEmpty(); !errors.Is(err, io.EOF) {
		t.Fatalf("closed ready pipe: %v", err)
	}
	if err := errors.Join(pipes.readyRead.Close(), pipes.gateRead.Close(), pipes.gateWrite.Close()); err != nil {
		t.Fatalf("close pipes: %v", err)
	}
	if err := pollPipe(-1, time.Now().Add(time.Second)); !errors.Is(err, unix.EOVERFLOW) {
		t.Fatalf("invalid poll descriptor: %v", err)
	}
	if waitClone3Command(&exec.Cmd{}) {
		t.Fatal("unstarted command reported reaped")
	}
	child := clone3Child{command: &exec.Cmd{}, pidfd: -1}
	if child.reap(time.Now().Add(time.Second)) {
		t.Fatal("unstarted child reported reaped")
	}
}

func TestClone3MembershipRequiresPID(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("41\n42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCgroupDirectory(t, directory)
	leaf := ownedCgroupLeaf{fd: directory.fd}
	if err := verifyClone3Membership(leaf, 42); err != nil {
		t.Fatalf("present PID rejected: %v", err)
	}
	if err := verifyClone3Membership(leaf, 7); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("absent PID error = %v", err)
	}
}

func TestClone3CleanupClassifiesCompleteTree(t *testing.T) {
	leaf := cleanupTestLeaf(t)
	pipes, err := newClone3Pipes()
	if err != nil {
		t.Fatal(err)
	}
	if err := pipes.closeChildEnds(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "/bin/true")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	child := clone3Child{command: command, pidfd: -1, pipes: pipes}
	result := cleanupClone3Child(passedCgroup(), leaf, &child, time.Now().Add(time.Second))
	if !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
}

func TestClone3CleanupClassifiesIncompleteTree(t *testing.T) {
	command := exec.CommandContext(t.Context(), "/bin/true")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	pipes, err := newClone3Pipes()
	if err != nil {
		t.Fatal(err)
	}
	if err := pipes.closeChildEnds(); err != nil {
		t.Fatal(err)
	}
	child := clone3Child{command: command, pidfd: -1, pipes: pipes}
	result := cleanupClone3Child(passedCgroup(), ownedCgroupLeaf{fd: -1}, &child, time.Now())
	if !result.CleanupAttempted || result.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
}

func cleanupTestLeaf(t *testing.T) ownedCgroupLeaf {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.kill"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.events"), []byte("populated 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close cleanup leaf: %v", err)
		}
	})
	return ownedCgroupLeaf{fd: fd}
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

func TestClone3LeafRejectsMissingExecutable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pids.max"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCgroupDirectory(t, directory)
	fixture, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	command := exec.CommandContext(t.Context(), "/missing-celestia-helper")
	result := runClone3Leaf(ownedCgroupLeaf{fd: directory.fd}, command, fixture)
	if result.Outcome != "indeterminate" || result.Reason != "clone3_start_indeterminate" {
		t.Fatalf("result=%+v", result)
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

func TestClone3LeafStateFailures(t *testing.T) {
	failure := errors.New("clone3 leaf failure")
	tests := map[string]struct {
		mutate  func(*clone3LeafOps, *clone3Child)
		outcome string
		reason  string
		cleanup bool
	}{
		"limit": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.writeLimit = func() error { return failure }
		}, "indeterminate", "clone3_process_limit_indeterminate", false},
		"start": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.start = func() (*clone3Child, error) { return nil, failure }
		}, "indeterminate", "clone3_start_indeterminate", false},
		"partial start": {func(ops *clone3LeafOps, child *clone3Child) {
			ops.start = func() (*clone3Child, error) { return child, failure }
		}, "indeterminate", "clone3_start_indeterminate", true},
		"pidfd": {func(_ *clone3LeafOps, child *clone3Child) {
			child.pidfd = -1
		}, "unavailable", "clone3_pidfd_unavailable", true},
		"membership": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.membership = func(*clone3Child) error { return failure }
		}, "indeterminate", "clone3_membership_indeterminate", true},
		"freeze": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.freeze = func(time.Time) error { return failure }
		}, "indeterminate", "cgroup_freeze_indeterminate", true},
		"before freeze": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.readyEmpty = func(*clone3Child) error { return failure }
		}, "indeterminate", "clone3_payload_before_freeze", true},
		"release": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.release = func(*clone3Child) error { return failure }
		}, "indeterminate", "clone3_gate_release_failed", true},
		"before thaw": {func(ops *clone3LeafOps, _ *clone3Child) {
			calls := 0
			ops.readyEmpty = func(*clone3Child) error {
				calls++
				if calls == 2 {
					return failure
				}
				return nil
			}
		}, "indeterminate", "clone3_payload_before_thaw", true},
		"thaw": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.thaw = func(time.Time) error { return failure }
		}, "indeterminate", "cgroup_freeze_indeterminate", true},
		"ready": {func(ops *clone3LeafOps, _ *clone3Child) {
			ops.waitReady = func(*clone3Child, time.Time) error { return failure }
		}, "indeterminate", "clone3_gate_indeterminate", true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			child := &clone3Child{pidfd: 1}
			cleaned := false
			operations := successfulClone3LeafOps(child, &cleaned)
			test.mutate(&operations, child)
			result := runClone3LeafWith(operations, time.Now().Add(time.Second))
			if result.Outcome != test.outcome || result.Reason != test.reason || cleaned != test.cleanup {
				t.Fatalf("result=%+v cleaned=%t", result, cleaned)
			}
		})
	}
	cleaned := false
	child := &clone3Child{pidfd: 1}
	result := runClone3LeafWith(successfulClone3LeafOps(child, &cleaned), time.Now().Add(time.Second))
	if result.Outcome != "passed" || result.Reason != "clone3_gate_proved" || !cleaned {
		t.Fatalf("result=%+v cleaned=%t", result, cleaned)
	}
}

func successfulClone3LeafOps(child *clone3Child, cleaned *bool) clone3LeafOps {
	return clone3LeafOps{
		writeLimit: func() error { return nil },
		start:      func() (*clone3Child, error) { return child, nil },
		cleanup: func(result cgroupResult, _ *clone3Child) cgroupResult {
			*cleaned = true
			return result
		},
		membership: func(*clone3Child) error { return nil },
		readyEmpty: func(*clone3Child) error { return nil },
		release:    func(*clone3Child) error { return nil },
		waitReady:  func(*clone3Child, time.Time) error { return nil },
		freeze:     func(time.Time) error { return nil },
		thaw:       func(time.Time) error { return nil },
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
	command := exec.CommandContext(t.Context(), "/proc/self/exe")
	command.Args = append(command.Args, "-test.run="+testName, "--", argument)
	return command
}

func clone3CoverageHelperCommand(t *testing.T, testName, argument string) *exec.Cmd {
	t.Helper()
	command := clone3HelperCommand(t, testName, argument)
	path := os.Getenv("GOCOVERDIR")
	if path == "" {
		return command
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open coverage directory: %v", err)
	}
	directory := os.NewFile(uintptr(fd), "coverage-directory")
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close coverage directory: %v", err)
		}
	})
	command.Stdin = directory
	separator, helperArgument := command.Args[len(command.Args)-2], command.Args[len(command.Args)-1]
	command.Args = append(command.Args[:len(command.Args)-2],
		"-test.gocoverdir=/proc/self/fd/0", separator, helperArgument)
	return command
}
