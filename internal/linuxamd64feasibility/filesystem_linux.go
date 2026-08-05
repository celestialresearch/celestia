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

func rootFilesystem(name string) (string, error) {
	filesystem, err := filesystemType(name)
	if err != nil {
		return "", err
	}
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer mounts.Close()
	name, err = filepath.Abs(name)
	if err != nil {
		return "", err
	}
	mounted, err := mountedFilesystem(io.LimitReader(mounts, maxMountinfoBytes+1), filepath.Clean(name))
	if err != nil {
		return "", err
	}
	return evidenceFilesystem(filesystem, mounted), nil
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
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maxMountinfoBytes)
	bestMount := ""
	bestFilesystem := ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := fieldIndex(fields, "-")
		if len(fields) < 7 || separator < 6 || separator+1 >= len(fields) {
			return "", "", errors.New("malformed mountinfo")
		}
		mount := unescapeMountPath(fields[4])
		if containsPath(mount, target) && len(mount) > len(bestMount) {
			bestMount = mount
			bestFilesystem = fields[separator+1]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if bestMount == "" {
		return "", "", errors.New("mount not found")
	}
	return bestMount, bestFilesystem, nil
}

func fieldIndex(fields []string, value string) int {
	for index, field := range fields {
		if field == value {
			return index
		}
	}
	return -1
}

func unescapeMountPath(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
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
