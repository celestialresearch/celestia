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

//go:build linux

package linuxamd64feasibility

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	cgroup2Filesystem = 0x63677270
	ext4Filesystem    = 0xef53
	xfsFilesystem     = 0x58465342
	maxMountinfoBytes = 1 << 20
)

func cgroupV2(name string) (bool, error) {
	filesystem, err := filesystemType(name)
	return isCgroupV2(filesystem), err
}

// EvidenceFilesystem identifies a supported local evidence filesystem.
func EvidenceFilesystem(name string) (string, error) {
	filesystem, err := filesystemType(name)
	if err != nil {
		return "", err
	}
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	name, err = filepath.Abs(name)
	if err != nil {
		return "", err
	}
	mounted, parseErr := mountedFilesystem(io.LimitReader(mounts, maxMountinfoBytes+1), filepath.Clean(name))
	if err := errors.Join(parseErr, mounts.Close()); err != nil {
		return "", err
	}
	return evidenceFilesystem(filesystem, mounted), nil
}

func rootFilesystem(name string) (string, error) {
	return EvidenceFilesystem(name)
}

func isCgroupV2(filesystem int64) bool {
	return filesystem == cgroup2Filesystem
}

func evidenceFilesystem(filesystem int64, mounted string) string {
	switch {
	case filesystem == ext4Filesystem && mounted == "ext4":
		return "ext4"
	case filesystem == xfsFilesystem && mounted == "xfs":
		return "xfs"
	default:
		return "unsupported"
	}
}

func mountedFilesystem(reader io.Reader, target string) (string, error) {
	_, filesystem, err := mountedFilesystemIdentity(reader, target)
	return filesystem, err
}

func mountedFilesystemIdentity(reader io.Reader, target string) (string, string, error) {
	entry, err := mountedFilesystemEntry(reader, target)
	return entry.Mount, entry.Filesystem, err
}

type mountEntry struct {
	Mount      string
	Filesystem string
	Major      uint32
	Minor      uint32
}

func mountedFilesystemEntry(reader io.Reader, target string) (mountEntry, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maxMountinfoBytes)
	best := mountEntry{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := fieldIndex(fields, "-")
		if len(fields) < 7 || separator < 6 || separator+1 >= len(fields) {
			return mountEntry{}, errors.New("malformed mountinfo")
		}
		major, minor, err := mountDevice(fields[2])
		if err != nil {
			return mountEntry{}, err
		}
		mount, err := unescapeMountPath(fields[4])
		if err != nil {
			return mountEntry{}, err
		}
		if containsPath(mount, target) && len(mount) > len(best.Mount) {
			best = mountEntry{
				Mount:      mount,
				Filesystem: fields[separator+1],
				Major:      major,
				Minor:      minor,
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return mountEntry{}, err
	}
	if best.Mount == "" {
		return mountEntry{}, errors.New("mount not found")
	}
	return best, nil
}

func mountDevice(value string) (uint32, uint32, error) {
	majorText, minorText, found := strings.Cut(value, ":")
	if !found || majorText == "" || minorText == "" || strings.Contains(minorText, ":") {
		return 0, 0, errors.New("malformed mount device")
	}
	if !canonicalMountNumber(majorText) || !canonicalMountNumber(minorText) {
		return 0, 0, errors.New("malformed mount device")
	}
	major, err := strconv.ParseUint(majorText, 10, 32)
	if err != nil {
		return 0, 0, errors.New("malformed mount device")
	}
	minor, err := strconv.ParseUint(minorText, 10, 32)
	if err != nil {
		return 0, 0, errors.New("malformed mount device")
	}
	return uint32(major), uint32(minor), nil
}

func canonicalMountNumber(value string) bool {
	if len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}

func fieldIndex(fields []string, value string) int {
	for index, field := range fields {
		if field == value {
			return index
		}
	}
	return -1
}

func unescapeMountPath(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			if value[index] < 0x20 || value[index] == 0x7f {
				return "", errors.New("malformed mount path")
			}
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", errors.New("malformed mount path")
		}
		escape := value[index+1 : index+4]
		switch escape {
		case "011":
			result.WriteByte('\t')
		case "012":
			result.WriteByte('\n')
		case "040":
			result.WriteByte(' ')
		case "134":
			result.WriteByte('\\')
		default:
			return "", errors.New("malformed mount path")
		}
		index += 3
	}
	return result.String(), nil
}

func containsPath(mount, target string) bool {
	return target == mount || mount == "/" || strings.HasPrefix(target, mount+"/")
}

func filesystemType(name string) (int64, error) {
	var information unix.Statfs_t
	if err := unix.Statfs(name, &information); err != nil {
		return 0, err
	}
	return information.Type, nil
}
