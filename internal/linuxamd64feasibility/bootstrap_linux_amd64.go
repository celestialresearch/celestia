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
	if os.Getpid() != 1 {
		return unix.EINVAL
	}
	if err := unix.Sethostname([]byte(bootstrapHostname)); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := prepareClone3Filesystem(); err != nil {
		return err
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	if loopback.Flags&net.FlagUp != 0 {
		return errors.New("loopback is enabled")
	}
	return nil
}

func prepareClone3Filesystem() error {
	const mountFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if err := unix.Mount("tmpfs", "/tmp", "tmpfs", mountFlags, "size=16m,nr_inodes=1024,mode=0700"); err != nil {
		return err
	}
	if err := unix.Mkdir(bootstrapRoot, 0o700); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", bootstrapRoot, "tmpfs", mountFlags, "size=16m,nr_inodes=1024,mode=0700"); err != nil {
		return err
	}
	if err := unix.Mkdir(bootstrapOldRoot, 0o700); err != nil {
		return err
	}
	if err := unix.Mkdir(bootstrapProc, 0o500); err != nil {
		return err
	}
	if err := unix.Mount("proc", bootstrapProc, "proc", mountFlags, ""); err != nil {
		return err
	}
	if err := unix.PivotRoot(bootstrapRoot, bootstrapOldRoot); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/old-root", unix.MNT_DETACH); err != nil {
		return err
	}
	return unix.Rmdir("/old-root")
}
