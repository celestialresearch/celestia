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
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

const requiredNamespaceFlags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS |
	syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS |
	syscall.CLONE_NEWNET

func configureClone3Namespaces(command *exec.Cmd, leaf ownedCgroupLeaf) error {
	uid, gid := unix.Getuid(), unix.Getgid()
	if uid < 0 || gid < 0 {
		return unix.EINVAL
	}
	command.Env = []string{"GOMAXPROCS=1"}
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 requiredNamespaceFlags,
		Credential:                 &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}},
		UseCgroupFD:                true,
		CgroupFD:                   leaf.fd,
	}
	return nil
}
