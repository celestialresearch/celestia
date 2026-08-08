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
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const bootstrapHostname = "celestia-feasibility"

const (
	bootstrapRoot    = "/tmp/celestia-root"
	bootstrapOldRoot = bootstrapRoot + "/old-root"
	bootstrapProc    = bootstrapRoot + "/proc"
)

func Bootstrap(gate, ready, fixture *os.File) error {
	if gate == nil || ready == nil || fixture == nil {
		return unix.EINVAL
	}
	err := runClone3Bootstrap(gate, ready, prepareClone3Namespace)
	if err != nil {
		return errors.Join(err, gate.Close(), ready.Close(), fixture.Close())
	}
	if err := unix.CloseRange(6, ^uint(0), unix.CLOSE_RANGE_UNSHARE); err != nil {
		return errors.Join(err, gate.Close(), ready.Close(), fixture.Close())
	}
	unix.CloseOnExec(int(fixture.Fd()))
	if err := errors.Join(gate.Close(), ready.Close()); err != nil {
		return errors.Join(err, fixture.Close())
	}
	err = unix.Exec("/proc/self/fd/5", []string{"celestia-hostile-fixture"}, []string{})
	return errors.Join(err, fixture.Close())
}

func prepareClone3Namespace() error {
	return prepareClone3NamespaceWith(bootstrapNamespaceOps{
		getpid: os.Getpid, sethostname: unix.Sethostname, mount: unix.Mount,
		filesystem: prepareClone3Filesystem, interfaceByName: net.InterfaceByName,
	})
}

type bootstrapNamespaceOps struct {
	getpid          func() int
	sethostname     func([]byte) error
	mount           func(string, string, string, uintptr, string) error
	filesystem      func() error
	interfaceByName func(string) (*net.Interface, error)
}

func prepareClone3NamespaceWith(operations bootstrapNamespaceOps) error {
	if operations.getpid() != 1 {
		return unix.EINVAL
	}
	if err := operations.sethostname([]byte(bootstrapHostname)); err != nil {
		return err
	}
	if err := operations.mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := operations.filesystem(); err != nil {
		return err
	}
	loopback, err := operations.interfaceByName("lo")
	if err != nil {
		return err
	}
	if loopback.Flags&net.FlagUp != 0 {
		return errors.New("loopback is enabled")
	}
	return nil
}

func prepareClone3Filesystem() error {
	return prepareClone3FilesystemWith(bootstrapFilesystemOps{
		mount: unix.Mount, mkdir: unix.Mkdir, pivotRoot: unix.PivotRoot,
		chdir: unix.Chdir, unmount: unix.Unmount, rmdir: unix.Rmdir,
	})
}

type bootstrapFilesystemOps struct {
	mount     func(string, string, string, uintptr, string) error
	mkdir     func(string, uint32) error
	pivotRoot func(string, string) error
	chdir     func(string) error
	unmount   func(string, int) error
	rmdir     func(string) error
}

func prepareClone3FilesystemWith(operations bootstrapFilesystemOps) error {
	const mountFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if err := operations.mount("tmpfs", "/tmp", "tmpfs", mountFlags, "size=16m,nr_inodes=1024,mode=0700"); err != nil {
		return err
	}
	if err := operations.mkdir(bootstrapRoot, 0o700); err != nil {
		return err
	}
	if err := operations.mount("tmpfs", bootstrapRoot, "tmpfs", mountFlags, "size=16m,nr_inodes=1024,mode=0700"); err != nil {
		return err
	}
	if err := operations.mkdir(bootstrapOldRoot, 0o700); err != nil {
		return err
	}
	if err := operations.mkdir(bootstrapProc, 0o500); err != nil {
		return err
	}
	if err := operations.mount("proc", bootstrapProc, "proc", mountFlags, ""); err != nil {
		return err
	}
	if err := operations.pivotRoot(bootstrapRoot, bootstrapOldRoot); err != nil {
		return err
	}
	if err := operations.chdir("/"); err != nil {
		return err
	}
	if err := operations.unmount("/old-root", unix.MNT_DETACH); err != nil {
		return err
	}
	return operations.rmdir("/old-root")
}
