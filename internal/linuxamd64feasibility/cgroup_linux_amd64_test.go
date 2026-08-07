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
	"time"

	"golang.org/x/sys/unix"
)

func TestBootstrapRejectsMissingFiles(t *testing.T) {
	if err := Bootstrap(nil, nil, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("Bootstrap() error = %v", err)
	}
}

func TestCgroupFailureResults(t *testing.T) {
	unknown := errors.New("unknown failure")
	tests := map[string]struct {
		result cgroupResult
		want   cgroupResult
	}{
		"open unavailable":   {cgroupOpenResult(unix.EPERM), unavailableCgroup("cgroup_root_unavailable")},
		"open indeterminate": {cgroupOpenResult(unknown), indeterminateCgroup("cgroup_root_indeterminate")},
		"leaf unavailable":   {cgroupLeafResult(unix.EROFS), unavailableCgroup("cgroup_leaf_unavailable")},
		"leaf indeterminate": {cgroupLeafResult(unknown), indeterminateCgroup("cgroup_leaf_indeterminate")},
		"read unavailable":   {cgroupReadResult(unix.ENOENT, "control"), unavailableCgroup("control_unavailable")},
		"read indeterminate": {cgroupReadResult(unknown, "control"), indeterminateCgroup("control_indeterminate")},
		"write unavailable": {cgroupWriteResult(unix.EACCES),
			unavailableCgroup("cgroup_leaf_controls_unavailable")},
		"write indeterminate": {cgroupWriteResult(unknown),
			indeterminateCgroup("cgroup_leaf_controls_indeterminate")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.result != test.want {
				t.Fatalf("result=%+v want=%+v", test.result, test.want)
			}
		})
	}
}

func TestCgroupInvalidLeaf(t *testing.T) {
	leaf := ownedCgroupLeaf{fd: -1}
	deadline := time.Now().Add(time.Second)
	for name, operation := range map[string]func() error{
		"freeze":     func() error { return leaf.freeze(deadline) },
		"thaw":       func() error { return leaf.thaw(deadline) },
		"wait empty": func() error { return leaf.waitEmpty(deadline) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	if found, err := leaf.containsPID(1); found || err == nil {
		t.Fatalf("contains PID = (%t, %v)", found, err)
	}
	if _, err := cgroupEvent(nil, "unknown"); !errors.Is(err, errCgroupEventsMalformed) {
		t.Fatalf("unknown event error = %v", err)
	}
}

func TestCgroupInvalidDescriptors(t *testing.T) {
	if _, err := pollDescriptor(-1); !errors.Is(err, unix.EOVERFLOW) {
		t.Fatalf("negative descriptor error = %v", err)
	}
	if _, err := pollDescriptor(1 << 31); !errors.Is(err, unix.EOVERFLOW) {
		t.Fatalf("oversized descriptor error = %v", err)
	}
	if descriptor, err := pollDescriptor(1); descriptor != 1 || err != nil {
		t.Fatalf("descriptor = (%d, %v)", descriptor, err)
	}
	if milliseconds, expired := pollMilliseconds(time.Now().Add(-time.Second)); milliseconds != 0 || !expired {
		t.Fatalf("expired poll = (%d, %t)", milliseconds, expired)
	}
	if count, err := readUnixFD(-1, make([]byte, 1)); count > 0 || err == nil {
		t.Fatalf("read = (%d, %v)", count, err)
	}
	if err := writeUnixFile(&unixFile{fd: -1}, []byte("x")); err == nil {
		t.Fatal("write to invalid descriptor succeeded")
	}
	if err := writeUnixFile(&unixFile{fd: -1}, nil); err != nil {
		t.Fatalf("empty write error = %v", err)
	}
}

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
	controls := []string{"pids.max", "memory.max", "memory.swap.max"}
	for _, name := range controls {
		writeLeafFile(t, leafPath, name, "")
	}
	defer func() {
		for _, name := range controls {
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
	assertLeafFile(t, leafPath, "pids.max", clone3FixtureTaskLimit)
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
