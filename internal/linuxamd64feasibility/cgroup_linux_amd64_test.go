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
	"io"
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
		if result.Outcome != expected.Outcome || result.Reason != expected.Reason {
			t.Fatalf("result=%+v expected=%+v", result, expected)
		}
		if !result.CleanupAttempted || !result.CleanupComplete {
			t.Fatalf("cleanup result=%+v", result)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatalf("entries=%v err=%v", entries, err)
		}
	}
}

func TestOwnedCgroupLeafRefusesReplacement(t *testing.T) {
	root := t.TempDir()
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer closeCgroupDirectory(t, directory)
	leaf, err := directory.createLeaf()
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	name := filepath.Join(root, leaf.name)
	replacement := name + "-replacement"
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatalf("create replacement: %v", err)
	}
	if err := os.Rename(name, name+"-original"); err != nil {
		t.Fatalf("rename leaf: %v", err)
	}
	if err := os.Rename(replacement, name); err != nil {
		t.Fatalf("replace leaf: %v", err)
	}
	if err := leaf.remove(); err == nil {
		t.Fatal("replacement removed")
	}
	if _, err := os.Stat(name); err != nil {
		t.Fatalf("replacement missing: %v", err)
	}
}

func TestCgroupLeafPreservesRefusalAfterCleanupFailure(t *testing.T) {
	root := t.TempDir()
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer closeCgroupDirectory(t, directory)
	result := useCgroupLeaf(directory, func(leaf ownedCgroupLeaf) cgroupResult {
		name := filepath.Join(root, leaf.name)
		if err := os.Rename(name, name+"-moved"); err != nil {
			t.Fatalf("move leaf: %v", err)
		}
		return unavailableCgroup("leaf_rejected")
	})
	if result.Outcome != "unavailable" || result.Reason != "leaf_rejected" ||
		!result.CleanupAttempted || result.CleanupComplete {
		t.Fatalf("result=%+v", result)
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
	defer removeMockCgroupFiles(t, leafPath)
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

func TestNativeFixtureMemoryLimitDisablesSwap(t *testing.T) {
	root := t.TempDir()
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer closeCgroupDirectory(t, directory)
	leaf, err := directory.createLeaf()
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafPath := filepath.Join(root, leaf.name)
	for _, name := range []string{"memory.max", "memory.swap.max"} {
		writeLeafFile(t, leafPath, name, "")
	}
	defer func() {
		for _, name := range []string{"memory.max", "memory.swap.max"} {
			if err := os.Remove(filepath.Join(leafPath, name)); err != nil {
				t.Errorf("remove %s: %v", name, err)
			}
		}
		if err := leaf.remove(); err != nil {
			t.Errorf("remove leaf: %v", err)
		}
	}()

	options := nativeFixtureOptions{memoryMax: nativeMemoryLimit}
	if result := applyNativeFixtureLimits(leaf, options); result.Outcome != "passed" {
		t.Fatalf("result=%+v", result)
	}
	assertLeafFile(t, leafPath, "memory.max", nativeMemoryLimit)
	assertLeafFile(t, leafPath, "memory.swap.max", "0")

	if err := os.Remove(filepath.Join(leafPath, "memory.swap.max")); err != nil {
		t.Fatalf("remove swap control: %v", err)
	}
	if result := applyNativeFixtureLimits(leaf, options); result.Outcome == "passed" {
		t.Fatal("missing swap control accepted")
	}
	writeLeafFile(t, leafPath, "memory.swap.max", "")
}

func assertLeafFile(t *testing.T, root, name, expected string) {
	t.Helper()
	directory, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open leaf root: %v", err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close leaf root: %v", err)
		}
	}()
	file, err := directory.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	data, readErr := io.ReadAll(file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if string(data) != expected {
		t.Fatalf("%s = %q, want %q", name, data, expected)
	}
}

func removeMockCgroupFiles(t *testing.T, leafPath string) {
	t.Helper()
	for _, name := range append([]string{"cgroup.events"}, cgroupLeafFiles[:]...) {
		if err := os.Remove(filepath.Join(leafPath, name)); err != nil {
			t.Errorf("remove %s: %v", name, err)
		}
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
			if closeErr := directory.close(); closeErr != nil {
				t.Errorf("close unsafe root: %v", closeErr)
			}
			t.Fatalf("opened unsafe root %q", value)
		}
	}
}

func closeCgroupDirectory(t *testing.T, directory cgroupDirectory) {
	t.Helper()
	if err := directory.close(); err != nil {
		t.Errorf("close root: %v", err)
	}
}

func writeLeafFile(t *testing.T, root, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
