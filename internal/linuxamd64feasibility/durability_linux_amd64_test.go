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
	"fmt"
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

func TestDurabilityRootClassification(t *testing.T) {
	tests := map[string]struct {
		err  error
		want durabilityResult
	}{
		"invalid": {errDurabilityRootInvalid, unavailableDurability("evidence_root_invalid")},
		"unsafe":  {errDurabilityRootUnsafe, unavailableDurability("evidence_root_unsafe")},
		"filesystem": {errDurabilityFilesystem,
			unavailableDurability("evidence_root_unsupported_filesystem")},
		"mount": {errDurabilityMountMismatch,
			unavailableDurability("evidence_root_unsupported_filesystem")},
		"unavailable":   {unix.EPERM, unavailableDurability("evidence_root_unsafe")},
		"indeterminate": {unix.EIO, indeterminateDurability("evidence_root_indeterminate")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if result := durabilityRootResult(test.err); result != test.want {
				t.Fatalf("result=%+v want=%+v", result, test.want)
			}
		})
	}
	if durabilityUnavailableError(nil) {
		t.Fatal("nil error classified unavailable")
	}
	if !durabilityUnavailableError(fmt.Errorf("wrapped: %w", unix.EROFS)) {
		t.Fatal("wrapped refusal classified indeterminate")
	}
	if !durabilityUnavailableError(errors.Join(unix.EPERM, unix.ENOENT)) {
		t.Fatal("joined refusals classified indeterminate")
	}
}

func TestDurabilityErrorBoundaries(t *testing.T) {
	if allDurabilityErrorsUnavailable(nil) {
		t.Fatal("empty joined error classified unavailable")
	}
	if allDurabilityErrorsUnavailable([]error{unix.EPERM, unix.EIO}) {
		t.Fatal("mixed joined error classified unavailable")
	}
	for _, err := range []error{
		unix.EACCES, unix.EINVAL, unix.ELOOP, unix.ENOENT, unix.ENOSYS,
		unix.ENOTDIR, unix.EOPNOTSUPP, unix.EPERM, unix.EROFS,
	} {
		if !durabilityUnavailableError(err) {
			t.Fatalf("error not classified unavailable: %v", err)
		}
	}
	if _, err := durabilityDescriptorPath(-1); err == nil {
		t.Fatal("invalid descriptor path accepted")
	}
}

func TestDurabilityComponentBoundaries(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "component")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close component: %v", err)
		}
	}()
	var fileStat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &fileStat); err != nil {
		t.Fatal(err)
	}
	if err := secureDurabilityComponent(int(file.Fd()), fileStat.Uid, false); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("regular component error = %v", err)
	}

	directory := t.TempDir()
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close directory: %v", err)
		}
	}()
	var directoryStat unix.Stat_t
	if err := unix.Fstat(fd, &directoryStat); err != nil {
		t.Fatal(err)
	}
	if err := secureDurabilityComponent(fd, directoryStat.Uid+1, true); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("foreign root error = %v", err)
	}
}

func TestDurabilityFilesystemDescriptorBoundaries(t *testing.T) {
	if _, err := durabilityRootFromFD(-1, 0); err == nil {
		t.Fatal("invalid root descriptor accepted")
	}
	if err := validateDurabilityFilesystem(-1, 0); err == nil {
		t.Fatal("invalid filesystem descriptor accepted")
	}
	root := filepath.Join(t.TempDir(), "deleted")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close deleted root: %v", err)
		}
	}()
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if _, err := durabilityDescriptorPath(fd); !errors.Is(err, errDurabilityMountMismatch) {
		t.Fatalf("deleted descriptor error = %v", err)
	}
}

func TestDurabilityDirectoryPermissionBoundaries(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close root: %v", err)
		}
	}()
	var information unix.Stat_t
	if err := unix.Fstat(fd, &information); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchmod(fd, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := secureDurabilityComponent(fd, information.Uid, true); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("writable root error = %v", err)
	}
	if err := secureDurabilityComponent(fd, information.Uid, false); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("non-sticky parent error = %v", err)
	}
	if err := unix.Fchmod(fd, unix.S_ISVTX|0o777); err != nil {
		t.Fatal(err)
	}
	if err := secureDurabilityComponent(fd, information.Uid, false); err != nil {
		t.Fatalf("sticky parent rejected: %v", err)
	}
}

func TestDurabilityRecordIdentityRejectsWrongTypes(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "identity")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close file: %v", err)
		}
	}()
	var fileStat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &fileStat); err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureDirectoryIdentity(int(file.Fd()), fileStat.Uid, fileStat.Dev); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("file accepted as directory: %v", err)
	}

	directory, _ := testDurabilityRoot(t)
	if _, err := fixtureFileIdentity(directory.fd, directory.euid, directory.device); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("directory accepted as file: %v", err)
	}
}

func TestDurabilityFixtureCreationRefusesInvalidRoots(t *testing.T) {
	root, _ := testDurabilityRoot(t)
	closedRoot := root
	closedRoot.fd = -1
	if _, err := closedRoot.createFixture(); err == nil {
		t.Fatal("fixture created through closed root")
	}

	secondRoot, path := testDurabilityRoot(t)
	name := "not-directory"
	if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openFixture(secondRoot, name); err == nil {
		t.Fatal("regular file opened as fixture directory")
	}
}

func TestDurabilityFixtureRejectsUnsafeDirectory(t *testing.T) {
	root, path := testDurabilityRoot(t)
	name := "unsafe-directory"
	directory := filepath.Join(path, name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(directory, 0o701); err != nil {
		t.Fatal(err)
	}
	if _, err := openFixture(root, name); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("unsafe fixture directory error = %v", err)
	}
}

func TestDurabilityPublicationRejectsInvalidState(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	if err := fixture.publish(); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("publish without temporary: %v", err)
	}
	if err := fixture.verify(); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("verify without final: %v", err)
	}
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	fixture.final = &fixtureFile{}
	if err := fixture.publish(); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("publish with final: %v", err)
	}
}

func TestDurabilityTemporaryRejectsExistingRecord(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	fd, err := unix.Openat(fixture.fd, durabilityTemporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if err := fixture.writeTemporary(); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("existing temporary error = %v", err)
	}
}

func TestDurabilityFailedWriteRejectsReplacement(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	fd, err := unix.Openat(fixture.fd, durabilityTemporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fixture.temporary = &fixtureFile{name: durabilityTemporary, identity: fileIdentity{}}
	if err := fixture.finishTemporaryFailure(fd, unix.EIO); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestDurabilityPublishRejectsChangedTemporary(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	fd, err := unix.Openat(fixture.fd, durabilityTemporary, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(writeAll(func(data []byte) (int, error) { return unix.Write(fd, data) }, []byte("x")), unix.Close(fd)); err != nil {
		t.Fatal(err)
	}
	if err := fixture.publish(); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("changed temporary accepted: %v", err)
	}
}

func TestDurabilityCleanupRejectsMissingOwnedNames(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	if err := unix.Unlinkat(fixture.fd, durabilityTemporary, 0); err != nil {
		t.Fatal(err)
	}
	if err := fixture.removeFile(*fixture.temporary); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing record error = %v", err)
	}
	rootPath, err := durabilityDescriptorPath(fixture.root.fd)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(rootPath, fixture.name+"-moved")
	defer func() {
		if err := os.RemoveAll(moved); err != nil {
			t.Errorf("remove moved fixture: %v", err)
		}
	}()
	if err := os.Rename(filepath.Join(rootPath, fixture.name), moved); err != nil {
		t.Fatal(err)
	}
	if err := fixture.namedIdentity(); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing fixture error = %v", err)
	}
}

func TestDurabilityFixtureCloseIsIdempotent(t *testing.T) {
	fixture := ownedFixture{fd: -1}
	if err := fixture.close(); err != nil {
		t.Fatalf("closed fixture: %v", err)
	}
}

func TestDurabilityVerificationRejectsChangedContent(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	if err := fixture.publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	fd, err := unix.Openat(fixture.fd, durabilityRecord, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open record: %v", err)
	}
	if err := errors.Join(writeAll(func(data []byte) (int, error) { return unix.Write(fd, data) }, []byte("changed")), unix.Close(fd)); err != nil {
		t.Fatalf("change record: %v", err)
	}
	if err := fixture.verify(); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("changed record accepted: %v", err)
	}
}

func TestDurabilityVerificationRejectsSameSizeSubstitution(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	if err := fixture.publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	fd, err := unix.Openat(fixture.fd, durabilityRecord, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open record: %v", err)
	}
	replacement := strings.Repeat("x", len(durabilityRecordData))
	if err := errors.Join(writeAll(func(data []byte) (int, error) { return unix.Write(fd, data) }, []byte(replacement)), unix.Close(fd)); err != nil {
		t.Fatalf("replace record: %v", err)
	}
	if err := fixture.verify(); !errors.Is(err, errDurabilityRootUnsafe) {
		t.Fatalf("substituted record accepted: %v", err)
	}
}

func TestDurabilityVerificationRejectsMissingRecord(t *testing.T) {
	fixture, cleanup := testOwnedFixture(t)
	defer cleanup()
	if err := fixture.writeTemporary(); err != nil {
		t.Fatalf("write temporary: %v", err)
	}
	if err := fixture.publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := unix.Unlinkat(fixture.fd, durabilityRecord, 0); err != nil {
		t.Fatalf("remove record: %v", err)
	}
	if err := fixture.verify(); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing final state accepted: %v", err)
	}
}

func TestDurabilityReadRejectsOversizedRecord(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "oversized")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close file: %v", err)
		}
	}()
	if _, err := file.Write([]byte("too large")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := readDurabilityFile(int(file.Fd()), 3); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("oversized record error = %v", err)
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

func TestDurabilityCleanupRemovesPartialOwnedTemporary(t *testing.T) {
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
	fd, err := unix.Openat(fixture.fd, durabilityTemporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fixtureFileIdentity(fd, fixture.root.euid, fixture.root.device)
	if err != nil {
		t.Fatal(errors.Join(err, unix.Close(fd)))
	}
	fixture.temporary = &fixtureFile{name: durabilityTemporary, identity: identity}
	if _, err := unix.Write(fd, []byte("partial")); err != nil {
		t.Fatal(errors.Join(err, unix.Close(fd)))
	}
	if err := fixture.finishTemporaryFailure(fd, unix.EIO); !errors.Is(err, unix.EIO) {
		t.Fatalf("finish failure: %v", err)
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
	replacement, err := unix.Openat(
		fixture.root.fd, fixture.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		t.Fatalf("open retained fixture: %v", err)
	}
	defer func() {
		if err := unix.Close(replacement); err != nil {
			t.Errorf("close retained fixture: %v", err)
		}
	}()
	data := readTestFixtureFile(t, replacement, durabilityTemporary)
	if string(data) != "replacement" {
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

func testOwnedFixture(t *testing.T) (ownedFixture, func()) {
	t.Helper()
	root, rootPath := testDurabilityRoot(t)
	fixture, err := root.createFixture()
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	return fixture, func() {
		if err := os.RemoveAll(filepath.Join(rootPath, fixture.name)); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	}
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
