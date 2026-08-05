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
	"testing"
)

func TestFilesystemClassification(t *testing.T) {
	if !isCgroupV2(cgroup2Filesystem) || isCgroupV2(ext4Filesystem) {
		t.Fatal("cgroup v2 filesystem classification failed")
	}
	cases := map[int64]string{
		ext4Filesystem: "ext4",
		xfsFilesystem:  "xfs",
		0:              "unsupported",
	}
	for filesystem, expected := range cases {
		if actual := evidenceFilesystem(filesystem); actual != expected {
			t.Fatalf("filesystem=%x actual=%q expected=%q", filesystem, actual, expected)
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
