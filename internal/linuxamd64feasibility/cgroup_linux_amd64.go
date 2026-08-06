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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	cgroupLeafAttempts = 4
	cgroupLeafPrefix   = "celestia-feasibility-"
)

var cgroupLeafFiles = [...]string{
	"cgroup.kill",
	"cgroup.freeze",
	"pids.max",
	"memory.max",
	"cpu.max",
}

type cgroupDirectory struct {
	fd int
}

type ownedCgroupLeaf struct {
	root int
	fd   int
	name string
}

func passedCgroup() cgroupResult {
	return cgroupResult{Outcome: "passed", Reason: "cgroup_delegated"}
}

func indeterminateCgroup(reason string) cgroupResult {
	return cgroupResult{Outcome: "indeterminate", Reason: reason}
}

func cgroupPrimitive(root string) (result cgroupResult) {
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
	return useCgroupLeaf(directory, validateCgroupLeaf)
}

func openCgroupDirectory(root string) (cgroupDirectory, error) {
	if !path.IsAbs(root) {
		return cgroupDirectory{}, unix.EINVAL
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return cgroupDirectory{}, err
	}
	for part := range strings.SplitSeq(strings.TrimPrefix(root, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return cgroupDirectory{}, errors.Join(unix.EINVAL, unix.Close(fd))
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return cgroupDirectory{}, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return cgroupDirectory{}, errors.Join(closeErr, unix.Close(next))
		}
		fd = next
	}
	return cgroupDirectory{fd: fd}, nil
}

func (directory cgroupDirectory) close() error {
	return unix.Close(directory.fd)
}

func validateDelegatedCgroup(directory cgroupDirectory) cgroupResult {
	root, err := directory.mountRoot()
	if err != nil {
		return indeterminateCgroup("cgroup_root_indeterminate")
	}
	if root {
		return unavailableCgroup("cgroup_root_not_delegated")
	}
	var information unix.Statfs_t
	if err := unix.Fstatfs(directory.fd, &information); err != nil {
		return indeterminateCgroup("cgroup_filesystem_indeterminate")
	}
	if !isCgroupV2(information.Type) {
		return unavailableCgroup("cgroup_v2_missing")
	}
	controllers, err := directory.read("cgroup.controllers", maxCgroupBytes)
	if err != nil {
		return cgroupReadResult(err, "cgroup_controllers")
	}
	if !requiredDelegatedControllers(controllers) {
		return unavailableCgroup("cgroup_controllers_unavailable")
	}
	delegated, err := directory.read("cgroup.subtree_control", maxCgroupBytes)
	if err != nil {
		return cgroupReadResult(err, "cgroup_delegation")
	}
	if !requiredDelegatedControllers(delegated) {
		return unavailableCgroup("cgroup_delegation_missing")
	}
	return passedCgroup()
}

func (directory cgroupDirectory) mountRoot() (bool, error) {
	resolved, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(directory.fd))
	if err != nil {
		return false, err
	}
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	mount, _, parseErr := mountedFilesystemIdentity(
		io.LimitReader(mounts, maxMountinfoBytes+1),
		path.Clean(resolved),
	)
	err = errors.Join(parseErr, mounts.Close())
	return err == nil && mount == path.Clean(resolved), err
}

func (directory cgroupDirectory) createLeaf() (ownedCgroupLeaf, error) {
	for range cgroupLeafAttempts {
		name, err := cgroupLeafName()
		if err != nil {
			return ownedCgroupLeaf{}, err
		}
		if err := unix.Mkdirat(directory.fd, name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return ownedCgroupLeaf{}, err
		}
		fd, err := unix.Openat(directory.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			removeErr := unix.Unlinkat(directory.fd, name, unix.AT_REMOVEDIR)
			return ownedCgroupLeaf{}, errors.Join(err, removeErr)
		}
		return ownedCgroupLeaf{root: directory.fd, fd: fd, name: name}, nil
	}
	return ownedCgroupLeaf{}, unix.EEXIST
}

func useCgroupLeaf(directory cgroupDirectory, validate func(ownedCgroupLeaf) cgroupResult) cgroupResult {
	leaf, err := directory.createLeaf()
	if err != nil {
		return cgroupLeafResult(err)
	}
	result := validate(leaf)
	completed := leaf.remove() == nil
	if result.CleanupAttempted {
		result.CleanupComplete = result.CleanupComplete && completed
		return result
	}
	result.CleanupAttempted = true
	result.CleanupComplete = completed
	return result
}

func cgroupLeafName() (string, error) {
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return cgroupLeafPrefix + hex.EncodeToString(token[:]), nil
}

func validateCgroupLeaf(leaf ownedCgroupLeaf) cgroupResult {
	events, err := leaf.read("cgroup.events", maxCgroupEventsBytes)
	if err != nil {
		return cgroupReadResult(err, "cgroup_events")
	}
	populated, err := cgroupPopulated(events)
	if err != nil {
		return indeterminateCgroup("cgroup_events_malformed")
	}
	if populated {
		return unavailableCgroup("cgroup_leaf_populated")
	}
	for _, name := range cgroupLeafFiles {
		if err := leaf.writable(name); err != nil {
			return cgroupWriteResult(err)
		}
	}
	return passedCgroup()
}

func (leaf ownedCgroupLeaf) remove() error {
	owned, identityErr := leaf.namedIdentity()
	if identityErr != nil || !owned {
		return errors.Join(identityErr, unix.ESTALE, unix.Close(leaf.fd))
	}
	closeErr := unix.Close(leaf.fd)
	removeErr := unix.Unlinkat(leaf.root, leaf.name, unix.AT_REMOVEDIR)
	return errors.Join(closeErr, removeErr)
}

func (leaf ownedCgroupLeaf) namedIdentity() (bool, error) {
	var opened, named unix.Stat_t
	if err := unix.Fstat(leaf.fd, &opened); err != nil {
		return false, err
	}
	if err := unix.Fstatat(leaf.root, leaf.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	return opened.Dev == named.Dev && opened.Ino == named.Ino, nil
}

func (directory cgroupDirectory) read(name string, limit int) ([]byte, error) {
	fd, err := unix.Openat(directory.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := unixFile{fd: fd}
	data, readErr := io.ReadAll(io.LimitReader(&file, int64(limit)+1))
	closeErr := file.Close()
	return data, errors.Join(readErr, closeErr)
}

func (leaf ownedCgroupLeaf) read(name string, limit int) ([]byte, error) {
	return cgroupDirectory{fd: leaf.fd}.read(name, limit)
}

func (leaf ownedCgroupLeaf) writable(name string) error {
	fd, err := unix.Openat(leaf.fd, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func (leaf ownedCgroupLeaf) write(name string, data []byte) error {
	fd, err := unix.Openat(leaf.fd, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := unixFile{fd: fd}
	writeErr := writeUnixFile(&file, data)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func cgroupOpenResult(err error) cgroupResult {
	if cgroupUnavailableError(err) {
		return unavailableCgroup("cgroup_root_unavailable")
	}
	return indeterminateCgroup("cgroup_root_indeterminate")
}

func cgroupLeafResult(err error) cgroupResult {
	if cgroupUnavailableError(err) {
		return unavailableCgroup("cgroup_leaf_unavailable")
	}
	return indeterminateCgroup("cgroup_leaf_indeterminate")
}

func cgroupReadResult(err error, prefix string) cgroupResult {
	if cgroupUnavailableError(err) {
		return unavailableCgroup(prefix + "_unavailable")
	}
	return indeterminateCgroup(prefix + "_indeterminate")
}

func cgroupWriteResult(err error) cgroupResult {
	if cgroupUnavailableError(err) {
		return unavailableCgroup("cgroup_leaf_controls_unavailable")
	}
	return indeterminateCgroup("cgroup_leaf_controls_indeterminate")
}

func cgroupUnavailableError(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EBUSY) ||
		errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ELOOP) ||
		errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EROFS)
}

type unixFile struct {
	fd int
}

func (file *unixFile) Read(data []byte) (int, error) {
	for {
		count, err := unix.Read(file.fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return count, err
	}
}

func (file *unixFile) Close() error {
	return unix.Close(file.fd)
}

func writeUnixFile(file *unixFile, data []byte) error {
	for len(data) != 0 {
		count, err := unix.Write(file.fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
