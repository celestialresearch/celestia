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
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDurabilityPrimitiveRefusesInvalidRoot(t *testing.T) {
	result := durabilityPrimitive("/")
	if result.Outcome != "unavailable" || result.Reason != "evidence_root_invalid" ||
		result.CleanupAttempted {
		t.Fatalf("result=%+v", result)
	}
}

func TestDurabilityPrimitiveRefusesLinkedRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "evidence")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create link: %v", err)
	}
	result := durabilityPrimitive(link)
	if result.Outcome != "unavailable" || result.Reason != "evidence_root_unsafe" ||
		result.CleanupAttempted {
		t.Fatalf("result=%+v", result)
	}
}

func TestDurabilityPrimitiveMatchesNativeFilesystem(t *testing.T) {
	root := t.TempDir()
	filesystem, err := rootFilesystem(root)
	if err != nil {
		t.Fatalf("inspect filesystem: %v", err)
	}
	result := durabilityPrimitive(root)
	if filesystem == "ext4" || filesystem == "xfs" {
		if result.Outcome != "passed" || result.Reason != "durability_primitives_passed" ||
			!result.CleanupAttempted || !result.CleanupComplete {
			t.Fatalf("filesystem=%q result=%+v", filesystem, result)
		}
		return
	}
	if result.Outcome != "unavailable" || result.Reason != "evidence_root_unsupported_filesystem" ||
		!result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("filesystem=%q result=%+v", filesystem, result)
	}
}

func TestDurabilityRootRequiresCanonicalAbsolutePath(t *testing.T) {
	invalid := []string{
		"", "/", "relative", "/tmp/../evidence", "/tmp//evidence", "/tmp/./evidence",
		"/tmp/" + strings.Repeat("a", maxDurabilityNameBytes+1),
		"/" + strings.Repeat("a/", maxDurabilityComponents) + "a",
		"/tmp/a\x00b",
	}
	for _, name := range invalid {
		if _, err := durabilityRootParts(name); !errors.Is(err, errDurabilityRootInvalid) {
			t.Fatalf("name=%q err=%v", name, err)
		}
	}
	parts, err := durabilityRootParts("/var/lib/celestia")
	if err != nil || len(parts) != 3 || parts[0] != "var" || parts[2] != "celestia" {
		t.Fatalf("parts=%v err=%v", parts, err)
	}
}

func TestDurabilityWriteHandlesPartialAndInterruptedWrites(t *testing.T) {
	calls := 0
	err := writeAll(func(data []byte) (int, error) {
		calls++
		if calls == 1 {
			return 0, unix.EINTR
		}
		return min(2, len(data)), nil
	}, []byte("record"))
	if err != nil || calls != 4 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if err := writeAll(func([]byte) (int, error) { return 0, nil }, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write err=%v", err)
	}
	if err := writeAll(func(data []byte) (int, error) { return len(data) + 1, nil }, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("oversized write err=%v", err)
	}
}

func TestUnixReadReturnsEOF(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "read-eof")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	if count, err := readUnixFD(int(file.Fd()), make([]byte, 1)); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read = (%d, %v)", count, err)
	}
}

func TestDurabilityFailureClassification(t *testing.T) {
	unavailable := durabilityFailure(unix.EROFS, "unavailable", "indeterminate")
	if unavailable.Outcome != "unavailable" || unavailable.Reason != "unavailable" {
		t.Fatalf("unavailable=%+v", unavailable)
	}
	indeterminate := durabilityFailure(unix.EIO, "unavailable", "indeterminate")
	if indeterminate.Outcome != "indeterminate" || indeterminate.Reason != "indeterminate" {
		t.Fatalf("indeterminate=%+v", indeterminate)
	}
	joined := durabilityFailure(errors.Join(unix.EROFS, unix.EIO), "unavailable", "indeterminate")
	if joined.Outcome != "indeterminate" || joined.Reason != "indeterminate" {
		t.Fatalf("joined=%+v", joined)
	}
}

func TestDurabilityPublishDoesNotReplace(t *testing.T) {
	root, rootPath := testDurabilityRoot(t)
	fixture, err := root.createFixture()
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(filepath.Join(rootPath, fixture.name)); err != nil {
			t.Errorf("remove fixture path: %v", err)
		}
	})
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	final, err := unix.Openat(
		fixture.fd, durabilityRecord,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		t.Fatalf("create final: %v", err)
	}
	if err := writeAll(func(data []byte) (int, error) { return unix.Write(final, data) }, []byte("existing")); err != nil {
		t.Fatalf("write final: %v", errors.Join(err, unix.Close(final)))
	}
	if err := errors.Join(unix.Fsync(final), unix.Close(final)); err != nil {
		t.Fatalf("sync final: %v", err)
	}
	if err := fixture.publish(); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("publish err=%v", err)
	}
	if data := readTestFixtureFile(t, fixture.fd, durabilityRecord); string(data) != "existing" {
		t.Fatalf("data=%q", data)
	}
	if err := unix.Unlinkat(fixture.fd, durabilityRecord, 0); err != nil {
		t.Fatalf("remove final: %v", err)
	}
	if err := fixture.remove(); err != nil {
		t.Fatalf("remove fixture: %v", err)
	}
}

func TestDurabilityCleanupRefusesReplacement(t *testing.T) {
	root, rootPath := testDurabilityRoot(t)
	fixture, err := root.createFixture()
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	fixturePath := filepath.Join(rootPath, fixture.name)
	t.Cleanup(func() {
		if err := os.RemoveAll(fixturePath); err != nil {
			t.Errorf("remove fixture path: %v", err)
		}
	})
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	if err := os.Rename(
		filepath.Join(fixturePath, durabilityTemporary),
		filepath.Join(fixturePath, durabilityTemporary+".owned"),
	); err != nil {
		t.Fatalf("move temporary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixturePath, durabilityTemporary), []byte("replacement"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := fixture.remove(); err == nil {
		t.Fatal("replacement removed")
	}
	if data := readTestFixtureFile(t, fixture.fd, durabilityTemporary); string(data) != "replacement" {
		t.Fatalf("replacement=%q", data)
	}
}

func testDurabilityRoot(t *testing.T) (durabilityRoot, string) {
	t.Helper()
	name := t.TempDir()
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close root: %v", err)
		}
	})
	var information unix.Stat_t
	if err := unix.Fstat(fd, &information); err != nil {
		t.Fatalf("stat root: %v", err)
	}
	return durabilityRoot{fd: fd, device: information.Dev, euid: information.Uid}, name
}

func readTestFixtureFile(t *testing.T, root int, name string) []byte {
	t.Helper()
	fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	data, readErr := readDurabilityFile(fd, len(durabilityRecordData))
	if err := errors.Join(readErr, unix.Close(fd)); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
