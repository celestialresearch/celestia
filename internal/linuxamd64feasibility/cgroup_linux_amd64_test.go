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
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedCgroupLeafRemovesCreatedDirectory(t *testing.T) {
	root := t.TempDir()
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() {
		if err := directory.close(); err != nil {
			t.Errorf("close root: %v", err)
		}
	}()
	for _, expected := range []cgroupResult{passedCgroup(), unavailableCgroup("leaf_rejected")} {
		result := useCgroupLeaf(directory, func(leaf ownedCgroupLeaf) cgroupResult {
			leafPath := filepath.Join(root, leaf.name)
			if _, err := os.Lstat(leafPath); err != nil {
				t.Fatalf("stat leaf: %v", err)
			}
			return expected
		})
		if result != expected {
			t.Fatalf("result=%+v expected=%+v", result, expected)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatalf("entries=%v err=%v", entries, err)
		}
	}
}

func TestCgroupLeafRequiresEmptyEventsAndControls(t *testing.T) {
	root := t.TempDir()
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() {
		if err := directory.close(); err != nil {
			t.Errorf("close root: %v", err)
		}
	}()
	leaf, err := directory.createLeaf()
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	defer func() {
		if err := leaf.remove(); err != nil {
			t.Errorf("remove leaf: %v", err)
		}
	}()
	leafPath := filepath.Join(root, leaf.name)
	writeLeafFile(t, leafPath, "cgroup.events", "populated 0\nfrozen 0\n")
	for _, name := range cgroupLeafFiles {
		writeLeafFile(t, leafPath, name, "")
	}
	if result := validateCgroupLeaf(leaf); result.Outcome != "passed" {
		t.Fatalf("result=%+v", result)
	}
	if err := os.WriteFile(filepath.Join(leafPath, "cgroup.events"), []byte("populated 1\n"), 0o600); err != nil {
		t.Fatalf("rewrite events: %v", err)
	}
	if result := validateCgroupLeaf(leaf); result.Reason != "cgroup_leaf_populated" {
		t.Fatalf("result=%+v", result)
	}
}

func TestCgroupPrimitiveRefusesOrdinaryFilesystem(t *testing.T) {
	result := cgroupPrimitive(t.TempDir())
	if result.Outcome != "unavailable" || result.Reason != "cgroup_v2_missing" {
		t.Fatalf("result=%+v", result)
	}
}

func TestCgroupDirectoryDistinguishesFilesystemRoot(t *testing.T) {
	directory, err := openCgroupDirectory(t.TempDir())
	if err != nil {
		t.Fatalf("open directory: %v", err)
	}
	defer func() {
		if err := directory.close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	}()
	root, err := directory.mountRoot()
	if err != nil || root {
		t.Fatalf("root=%t err=%v", root, err)
	}
}

func TestCgroupDirectoryRefusesLinksAndParentTraversal(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("create link: %v", err)
	}
	for _, value := range []string{link, root + "/../root"} {
		directory, err := openCgroupDirectory(value)
		if err == nil {
			_ = directory.close()
			t.Fatalf("opened unsafe root %q", value)
		}
	}
}

func writeLeafFile(t *testing.T, root, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
