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
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	durabilityFixturePrefix = "celestia-durability-"
	durabilityTemporary     = ".record.tmp"
	durabilityRecord        = "record"
	durabilityRecordData    = "celestia-linux-amd64-feasibility\n"
	maxDurabilityComponents = 64
	maxDurabilityNameBytes  = 255
)

func passedDurability(reason string) durabilityResult {
	return durabilityResult{Outcome: "passed", Reason: reason}
}

func indeterminateDurability(reason string) durabilityResult {
	return durabilityResult{Outcome: "indeterminate", Reason: reason}
}

func durabilityName() (string, error) {
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return durabilityFixturePrefix + hex.EncodeToString(token[:]), nil
}

var (
	errDurabilityRootInvalid   = errors.New("invalid durability root")
	errDurabilityRootUnsafe    = errors.New("unsafe durability root")
	errDurabilityFilesystem    = errors.New("unsupported durability filesystem")
	errDurabilityMountMismatch = errors.New("durability mount mismatch")
)

type durabilityRoot struct {
	fd     int
	device uint64
	euid   uint32
}

func durabilityPrimitive(name string) (result durabilityResult) {
	root, err := openDurabilityRoot(name)
	if err != nil {
		return durabilityRootResult(err)
	}
	defer func() {
		result = finishDurabilityCleanup(result, root.close())
	}()
	fixture, err := root.createFixture()
	if err != nil {
		return durabilityFailure(err, "fixture_create_unavailable", "fixture_create_indeterminate")
	}
	defer func() {
		result = finishDurabilityCleanup(result, fixture.remove())
	}()
	if err := fixture.writeTemporary(); err != nil {
		return durabilityFailure(err, "file_fsync_unavailable", "file_write_indeterminate")
	}
	if err := fixture.publish(); err != nil {
		return durabilityFailure(err, "renameat2_noreplace_unavailable", "record_publish_indeterminate")
	}
	if err := fixture.verify(); err != nil {
		return indeterminateDurability("record_verify_indeterminate")
	}
	return passedDurability("durability_primitives_passed")
}

func durabilityFailure(err error, unavailable, indeterminate string) durabilityResult {
	if durabilityUnavailableError(err) {
		return unavailableDurability(unavailable)
	}
	return indeterminateDurability(indeterminate)
}

func durabilityUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		return allDurabilityErrorsUnavailable(joined.Unwrap())
	}
	if cause := errors.Unwrap(err); cause != nil {
		return durabilityUnavailableError(cause)
	}
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS)
}

func allDurabilityErrorsUnavailable(causes []error) bool {
	if len(causes) == 0 {
		return false
	}
	for _, cause := range causes {
		if !durabilityUnavailableError(cause) {
			return false
		}
	}
	return true
}

func durabilityRootResult(err error) durabilityResult {
	switch {
	case errors.Is(err, errDurabilityRootInvalid):
		return unavailableDurability("evidence_root_invalid")
	case errors.Is(err, errDurabilityRootUnsafe):
		return unavailableDurability("evidence_root_unsafe")
	case errors.Is(err, errDurabilityFilesystem), errors.Is(err, errDurabilityMountMismatch):
		return unavailableDurability("evidence_root_unsupported_filesystem")
	case durabilityUnavailableError(err):
		return unavailableDurability("evidence_root_unsafe")
	default:
		return indeterminateDurability("evidence_root_indeterminate")
	}
}

func openDurabilityRoot(name string) (durabilityRoot, error) {
	parts, err := durabilityRootParts(name)
	if err != nil {
		return durabilityRoot{}, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return durabilityRoot{}, err
	}
	euid := unix.Geteuid()
	if euid < 0 || uint64(euid) > uint64(^uint32(0)) {
		return durabilityRoot{}, errors.Join(errDurabilityRootUnsafe, unix.Close(fd))
	}
	owner := uint32(euid)
	for index, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return durabilityRoot{}, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return durabilityRoot{}, errors.Join(closeErr, unix.Close(next))
		}
		fd = next
		if err := secureDurabilityComponent(fd, owner, index == len(parts)-1); err != nil {
			return durabilityRoot{}, errors.Join(err, unix.Close(fd))
		}
	}
	root, err := durabilityRootFromFD(fd, owner)
	if err != nil {
		return durabilityRoot{}, errors.Join(err, unix.Close(fd))
	}
	return root, nil
}

func durabilityRootParts(name string) ([]string, error) {
	if len(name) == 0 || len(name) > maxRootBytes || !path.IsAbs(name) || name == "/" {
		return nil, errDurabilityRootInvalid
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	if len(parts) > maxDurabilityComponents {
		return nil, errDurabilityRootInvalid
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > maxDurabilityNameBytes ||
			strings.IndexByte(part, 0) >= 0 {
			return nil, errDurabilityRootInvalid
		}
	}
	return parts, nil
}

func secureDurabilityComponent(fd int, euid uint32, root bool) error {
	var information unix.Stat_t
	if err := unix.Fstat(fd, &information); err != nil {
		return err
	}
	if information.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errDurabilityRootUnsafe
	}
	if root {
		if information.Uid != euid || information.Mode&0o022 != 0 {
			return errDurabilityRootUnsafe
		}
		return nil
	}
	if information.Uid != 0 && information.Uid != euid {
		return errDurabilityRootUnsafe
	}
	if information.Mode&0o022 != 0 && information.Mode&unix.S_ISVTX == 0 {
		return errDurabilityRootUnsafe
	}
	return nil
}

func durabilityRootFromFD(fd int, euid uint32) (durabilityRoot, error) {
	var information unix.Stat_t
	if err := unix.Fstat(fd, &information); err != nil {
		return durabilityRoot{}, err
	}
	if err := validateDurabilityFilesystem(fd, information.Dev); err != nil {
		return durabilityRoot{}, err
	}
	return durabilityRoot{
		fd:     fd,
		device: information.Dev,
		euid:   euid,
	}, nil
}

func (root durabilityRoot) close() error {
	return unix.Close(root.fd)
}

func validateDurabilityFilesystem(fd int, device uint64) error {
	var information unix.Statfs_t
	if err := unix.Fstatfs(fd, &information); err != nil {
		return err
	}
	name, err := durabilityDescriptorPath(fd)
	if err != nil {
		return err
	}
	entry, err := durabilityMount(name)
	if err != nil {
		return err
	}
	if entry.Major != unix.Major(device) || entry.Minor != unix.Minor(device) {
		return errDurabilityMountMismatch
	}
	filesystem := evidenceFilesystem(information.Type, entry.Filesystem)
	if filesystem == "unsupported" {
		return errDurabilityFilesystem
	}
	return nil
}

func durabilityDescriptorPath(fd int) (string, error) {
	name, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "", err
	}
	if !path.IsAbs(name) || name != path.Clean(name) || strings.HasSuffix(name, " (deleted)") {
		return "", errDurabilityMountMismatch
	}
	return name, nil
}
