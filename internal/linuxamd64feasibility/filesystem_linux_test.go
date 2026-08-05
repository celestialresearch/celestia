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
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemClassification(t *testing.T) {
	if !isCgroupV2(cgroup2Filesystem) || isCgroupV2(ext4Filesystem) {
		t.Fatal("cgroup v2 filesystem classification failed")
	}
	cases := map[struct {
		magic int64
		name  string
	}]string{
		{ext4Filesystem, "ext4"}: "ext4",
		{ext4Filesystem, "ext3"}: "unsupported",
		{xfsFilesystem, "xfs"}:   "xfs",
		{0, "ext4"}:              "unsupported",
	}
	for filesystem, expected := range cases {
		if actual := evidenceFilesystem(filesystem.magic, filesystem.name); actual != expected {
			t.Fatalf("filesystem=%x name=%q actual=%q expected=%q", filesystem.magic, filesystem.name, actual, expected)
		}
	}
}

func TestMountedFilesystem(t *testing.T) {
	mountinfo := "1 0 8:1 / / rw - ext4 /dev/root rw\n" +
		"2 1 8:2 / /evidence rw - xfs /dev/data rw\n" +
		"3 2 8:3 / /evidence/nested rw - ext3 /dev/old rw\n"
	cases := map[string]string{"/other": "ext4", "/evidence/file": "xfs", "/evidence/nested/file": "ext3"}
	for target, expected := range cases {
		actual, err := mountedFilesystem(strings.NewReader(mountinfo), target)
		if err != nil || actual != expected {
			t.Fatalf("target=%q filesystem=%q error=%v", target, actual, err)
		}
	}
}

func TestMountedFilesystemIdentifiesMountRoot(t *testing.T) {
	mount, filesystem, err := mountedFilesystemIdentity(
		strings.NewReader("2 1 8:2 / /evidence rw - xfs /dev/data rw\n"),
		"/evidence",
	)
	if err != nil || mount != "/evidence" || filesystem != "xfs" {
		t.Fatalf("mount=%q filesystem=%q error=%v", mount, filesystem, err)
	}
}

func TestMountedFilesystemRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"invalid\n", strings.Repeat("a", maxMountinfoBytes+1)} {
		if _, err := mountedFilesystem(strings.NewReader(input), "/evidence"); err == nil {
			t.Fatal("invalid mountinfo accepted")
		}
	}
}

func TestFilesystemInspection(t *testing.T) {
	root := t.TempDir()
	if _, err := rootFilesystem(root); err != nil {
		t.Fatalf("root filesystem: %v", err)
	}
	if _, err := cgroupV2(root); err != nil {
		t.Fatalf("cgroup filesystem: %v", err)
	}
	missing := filepath.Join(root, "missing")
	if _, err := rootFilesystem(missing); err == nil {
		t.Fatal("missing root filesystem accepted")
	}
	if _, err := cgroupV2(missing); err == nil {
		t.Fatal("missing cgroup filesystem accepted")
	}
}
