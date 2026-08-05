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

import "golang.org/x/sys/unix"

const (
	cgroup2Filesystem = 0x63677270
	ext4Filesystem    = 0xef53
	xfsFilesystem     = 0x58465342
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
	return evidenceFilesystem(filesystem), nil
}

func isCgroupV2(filesystem int64) bool {
	return filesystem == cgroup2Filesystem
}

func evidenceFilesystem(filesystem int64) string {
	switch filesystem {
	case ext4Filesystem:
		return "ext4"
	case xfsFilesystem:
		return "xfs"
	default:
		return "unsupported"
	}
}

func filesystemType(name string) (int64, error) {
	var information unix.Statfs_t
	if err := unix.Statfs(name, &information); err != nil {
		return 0, err
	}
	return information.Type, nil
}
