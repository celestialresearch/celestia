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

func Bootstrap(gate, ready *os.File) error {
	if gate == nil || ready == nil {
		return unix.EINVAL
	}
	err := runClone3Bootstrap(gate, ready, prepareClone3Namespace)
	return errors.Join(err, gate.Close(), ready.Close())
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
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
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
