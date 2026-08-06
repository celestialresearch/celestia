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
	"time"

	"golang.org/x/sys/unix"
)

func (leaf ownedCgroupLeaf) freeze(deadline time.Time) error {
	if err := leaf.write("cgroup.freeze", []byte("1")); err != nil {
		return err
	}
	return leaf.waitEvent("frozen", true, deadline)
}

func (leaf ownedCgroupLeaf) thaw(deadline time.Time) error {
	if err := leaf.write("cgroup.freeze", []byte("0")); err != nil {
		return err
	}
	return leaf.waitEvent("frozen", false, deadline)
}

func (leaf ownedCgroupLeaf) waitEmpty(deadline time.Time) error {
	return leaf.waitEvent("populated", false, deadline)
}

func (leaf ownedCgroupLeaf) waitEvent(name string, want bool, deadline time.Time) error {
	for {
		data, err := leaf.read("cgroup.events", maxCgroupEventsBytes)
		if err != nil {
			return err
		}
		value, err := cgroupEvent(data, name)
		if err != nil || value == want {
			return err
		}
		if err := pollCgroupEvents(leaf.fd, deadline); err != nil {
			return err
		}
	}
}

func (leaf ownedCgroupLeaf) containsPID(pid int) (bool, error) {
	data, err := leaf.read("cgroup.procs", maxCgroupEventsBytes)
	if err != nil {
		return false, err
	}
	return cgroupContainsPID(data, pid)
}

func cgroupEvent(data []byte, name string) (bool, error) {
	switch name {
	case "frozen":
		return cgroupFrozen(data)
	case "populated":
		return cgroupPopulated(data)
	default:
		return false, errCgroupEventsMalformed
	}
}

func pollCgroupEvents(fd int, deadline time.Time) (result error) {
	watch, err := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	pollFD, err := pollDescriptor(watch)
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, unix.Close(watch))
	}()
	for {
		milliseconds, expired := pollMilliseconds(deadline)
		if expired {
			return errCgroupDeadlineExceeded
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: pollFD, Events: unix.POLLIN | unix.POLLPRI}}, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			return errCgroupDeadlineExceeded
		}
		return nil
	}
}

func pollDescriptor(fd int) (int32, error) {
	if fd < 0 || fd > 1<<31-1 {
		return 0, unix.EOVERFLOW
	}
	return int32(fd), nil
}

func pollMilliseconds(deadline time.Time) (int, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, true
	}
	milliseconds := int(remaining / time.Millisecond)
	if remaining%time.Millisecond != 0 {
		milliseconds++
	}
	return milliseconds, false
}
