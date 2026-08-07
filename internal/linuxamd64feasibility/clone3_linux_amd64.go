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
	"time"

	"golang.org/x/sys/unix"
)

const (
	clone3ProbeTimeout       = 2 * time.Second
	clone3BootstrapTaskLimit = "16"
	clone3FixtureTaskLimit   = "4"
)

type clone3Child struct {
	command *exec.Cmd
	pipes   clone3Pipes
	pidfd   int
}

func clone3CgroupPrimitive(root string, command *exec.Cmd, fixture *os.File) (result cgroupResult) {
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
		return runClone3Leaf(leaf, command, fixture)
	})
}

func runClone3Leaf(leaf ownedCgroupLeaf, command *exec.Cmd, fixture *os.File) (result cgroupResult) {
	deadline := time.Now().Add(clone3ProbeTimeout)
	return runClone3LeafWith(clone3LeafOps{
		writeLimit: func() error { return leaf.write("pids.max", []byte(clone3BootstrapTaskLimit)) },
		start:      func() (*clone3Child, error) { return startClone3Child(leaf, command, fixture) },
		cleanup: func(result cgroupResult, child *clone3Child) cgroupResult {
			return cleanupClone3Child(result, leaf, child, deadline)
		},
		membership: func(child *clone3Child) error {
			return verifyClone3Membership(leaf, child.command.Process.Pid)
		},
		readyEmpty: func(child *clone3Child) error { return child.pipes.readyEmpty() },
		release:    func(child *clone3Child) error { return child.pipes.release() },
		waitReady: func(child *clone3Child, deadline time.Time) error {
			return child.pipes.waitReady(deadline)
		},
		freeze: leaf.freeze, thaw: leaf.thaw,
	}, deadline)
}

type clone3LeafOps struct {
	writeLimit func() error
	start      func() (*clone3Child, error)
	cleanup    func(cgroupResult, *clone3Child) cgroupResult
	membership func(*clone3Child) error
	readyEmpty func(*clone3Child) error
	release    func(*clone3Child) error
	waitReady  func(*clone3Child, time.Time) error
	freeze     func(time.Time) error
	thaw       func(time.Time) error
}

func runClone3LeafWith(operations clone3LeafOps, deadline time.Time) (result cgroupResult) {
	if err := operations.writeLimit(); err != nil {
		return clone3LimitResult(err)
	}
	child, err := operations.start()
	if child == nil {
		return clone3StartResult(err)
	}
	defer func() {
		result = operations.cleanup(result, child)
	}()
	if err != nil {
		return clone3StartResult(err)
	}
	if child.pidfd < 0 {
		return unavailableCgroup("clone3_pidfd_unavailable")
	}
	if err := operations.membership(child); err != nil {
		return clone3MembershipResult(err)
	}
	if err := operations.freeze(deadline); err != nil {
		return clone3FreezeResult(err)
	}
	if err := operations.readyEmpty(child); err != nil {
		return indeterminateCgroup("clone3_payload_before_freeze")
	}
	if err := operations.release(child); err != nil {
		return indeterminateCgroup("clone3_gate_release_failed")
	}
	if err := operations.readyEmpty(child); err != nil {
		return indeterminateCgroup("clone3_payload_before_thaw")
	}
	if err := operations.thaw(deadline); err != nil {
		return clone3FreezeResult(err)
	}
	if err := operations.waitReady(child, deadline); err != nil {
		return clone3ReadyResult(err)
	}
	return cgroupResult{Outcome: "passed", Reason: "clone3_gate_proved"}
}

func startClone3Child(leaf ownedCgroupLeaf, command *exec.Cmd, fixture *os.File) (*clone3Child, error) {
	if command == nil || command.Path == "" || command.Process != nil ||
		len(command.ExtraFiles) != 0 || command.SysProcAttr != nil || fixture == nil {
		return nil, unix.EINVAL
	}
	pipes, err := newClone3Pipes()
	if err != nil {
		return nil, err
	}
	child := &clone3Child{pipes: pipes, pidfd: -1}
	child.command = command
	child.command.ExtraFiles = []*os.File{pipes.readyWrite, pipes.gateRead, fixture}
	if err := configureClone3Namespaces(child.command, leaf); err != nil {
		return nil, errors.Join(pipes.closeChildEnds(), pipes.closeParentEnds(), err)
	}
	child.command.SysProcAttr.PidFD = &child.pidfd
	if err := child.command.Start(); err != nil {
		return nil, errors.Join(pipes.closeChildEnds(), pipes.closeParentEnds(), err)
	}
	return child, pipes.closeChildEnds()
}

func verifyClone3Membership(leaf ownedCgroupLeaf, pid int) error {
	present, err := leaf.containsPID(pid)
	if err != nil {
		return err
	}
	if !present {
		return unix.ESRCH
	}
	return nil
}

func cleanupClone3Child(result cgroupResult, leaf ownedCgroupLeaf, child *clone3Child, deadline time.Time) cgroupResult {
	complete := true
	if err := leaf.write("cgroup.kill", []byte("1")); err != nil {
		complete = false
		var signalErr error
		if child.pidfd >= 0 {
			signalErr = unix.PidfdSendSignal(child.pidfd, unix.SIGKILL, nil, 0)
		} else {
			signalErr = child.command.Process.Kill()
		}
		if signalErr != nil {
			complete = false
		}
	}
	if !child.reap(deadline) {
		complete = false
	}
	if err := leaf.waitEmpty(deadline); err != nil {
		complete = false
	}
	if err := child.close(); err != nil {
		complete = false
	}
	result.CleanupAttempted = true
	result.CleanupComplete = complete
	return result
}

func (child *clone3Child) reap(deadline time.Time) bool {
	if child.pidfd < 0 {
		return waitClone3Command(child.command)
	}
	if err := pollPipe(child.pidfd, deadline); err != nil {
		return false
	}
	return waitClone3Command(child.command)
}

func waitClone3Command(command *exec.Cmd) bool {
	err := command.Wait()
	if err == nil {
		return true
	}
	if exitError, ok := errors.AsType[*exec.ExitError](err); ok && exitError != nil {
		return command.ProcessState != nil
	}
	return false
}

func (child *clone3Child) close() error {
	var pidfdErr error
	if child.pidfd >= 0 {
		pidfdErr = unix.Close(child.pidfd)
	}
	return errors.Join(child.pipes.closeParentEnds(), pidfdErr)
}

func clone3LimitResult(err error) cgroupResult {
	if cgroupUnavailableError(err) {
		return unavailableCgroup("clone3_process_limit_unavailable")
	}
	return indeterminateCgroup("clone3_process_limit_indeterminate")
}

func clone3StartResult(err error) cgroupResult {
	if errors.Is(err, unix.EACCES) {
		return unavailableCgroup("clone3_placement_denied")
	}
	if cgroupUnavailableError(err) || errors.Is(err, unix.ENOSYS) {
		return unavailableCgroup("clone3_unavailable")
	}
	return indeterminateCgroup("clone3_start_indeterminate")
}

func clone3MembershipResult(err error) cgroupResult {
	if cgroupUnavailableError(err) {
		return unavailableCgroup("clone3_membership_unavailable")
	}
	return indeterminateCgroup("clone3_membership_indeterminate")
}

func clone3FreezeResult(err error) cgroupResult {
	if cgroupUnavailableError(err) || errors.Is(err, errCgroupDeadlineExceeded) {
		return unavailableCgroup("cgroup_freeze_unavailable")
	}
	return indeterminateCgroup("cgroup_freeze_indeterminate")
}

func clone3ReadyResult(err error) cgroupResult {
	if errors.Is(err, errCgroupDeadlineExceeded) || errors.Is(err, unix.EPIPE) {
		return unavailableCgroup("clone3_gate_unavailable")
	}
	return indeterminateCgroup("clone3_gate_indeterminate")
}
