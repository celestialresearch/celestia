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
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFixturePathAndELFBoundaries(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{"", ".", "..", "../fixture", "/fixture", "a\x00b", "a/../fixture"} {
		if validFixturePath(root, relative) {
			t.Fatalf("invalid fixture path accepted: %q", relative)
		}
	}
	if !validFixturePath(root, "nested/fixture") {
		t.Fatal("valid fixture path rejected")
	}
	if snapshot, err := sealedFixtureSnapshot(nil); snapshot != nil || err == nil {
		t.Fatalf("nil snapshot = (%v, %v)", snapshot, err)
	}

	file, err := os.CreateTemp(t.TempDir(), "not-elf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	if _, err := staticELFType(file); err == nil {
		t.Fatal("non-ELF fixture accepted")
	}
	image := &elf.File{Progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_X}},
	}}
	if !hasExecutableLoad(image) {
		t.Fatal("executable load rejected")
	}
	if hasInterpreter(image) {
		t.Fatal("missing interpreter reported")
	}
	image.Progs = append(image.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_INTERP}})
	if !hasInterpreter(image) {
		t.Fatal("interpreter omitted")
	}
}

func TestOpenStaticFixtureBindsExactImage(t *testing.T) {
	root := t.TempDir()
	writeStaticTestExecutable(t, filepath.Join(root, "fixture"))
	file, identity, err := openStaticFixture(root, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if identity.ELFMachine != "x86_64" || identity.PTInterp ||
		(identity.ELFType != "ET_EXEC" && identity.ELFType != "ET_DYN") ||
		identity.Device == 0 || identity.Inode == 0 || len(identity.SHA256) != 64 {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestOpenStaticFixtureSealsSnapshot(t *testing.T) {
	root := t.TempDir()
	writeStaticTestExecutable(t, filepath.Join(root, "fixture"))
	file, _, err := openStaticFixture(root, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	if _, err := file.WriteAt([]byte{0}, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("write sealed fixture: %v", err)
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&fixtureSeals != fixtureSeals {
		t.Fatalf("seals=%#x error=%v", seals, err)
	}
}

func TestOpenStaticFixtureRejectsPathAndImageSubstitution(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeStaticTestExecutable(t, outside)
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(root, "text")
	if err := os.WriteFile(text, []byte("not ELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(text, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"../outside", "linked", "text", ".", "a/../text"} {
		file, _, err := openStaticFixture(root, relative)
		if file != nil || err == nil {
			t.Fatalf("relative=%q file=%v err=%v", relative, file, err)
		}
	}
}

func TestOpenStaticFixtureRejectsMutableImage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fixture")
	writeStaticTestExecutable(t, path)
	if err := unix.Chmod(path, 0o722); err != nil {
		t.Fatal(err)
	}
	file, _, err := openStaticFixture(root, "fixture")
	if file != nil || err == nil {
		t.Fatalf("file=%v err=%v", file, err)
	}
}

func TestOpenStaticFixtureRejectsLinkedRootComponent(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Fatal(err)
	}
	if file, _, err := openStaticFixture(link, "fixture"); file != nil || err == nil {
		t.Fatalf("file=%v err=%v", file, err)
	}
}

func TestFixtureRequiresOwnerExecutePermission(t *testing.T) {
	t.Parallel()

	const owner = uint32(1000)
	information := unix.Stat_t{
		Mode: unix.S_IFREG | 0o401, Uid: owner, Nlink: 1, Size: 1,
	}
	if validFixtureStat(information, owner) {
		t.Fatal("fixture without owner execute permission accepted")
	}
}

func TestFixtureRejectsInterpreter(t *testing.T) {
	image := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_INTERP}}}}
	if !hasInterpreter(image) {
		t.Fatal("interpreter accepted")
	}
}

func TestFixtureIdentityRejectsUnsealedDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(staticTestELF()); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := staticFixtureIdentity(file); err == nil {
		t.Fatal("unsealed fixture accepted")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := staticFixtureIdentity(file); err == nil {
		t.Fatal("closed fixture accepted")
	}
	if hasExecutableLoad(&elf.File{}) {
		t.Fatal("empty ELF has executable load")
	}
}

func writeStaticTestExecutable(t *testing.T, target string) {
	t.Helper()
	if err := os.WriteFile(target, staticTestELF(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fsync(int(mustOpenDirectory(t, filepath.Dir(target)).Fd())); err != nil {
		t.Fatal(err)
	}
}

func staticTestELF() []byte {
	const (
		headerSize  = 64
		programSize = 56
		baseAddress = 0x400000
	)
	code := []byte{0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05}
	data := make([]byte, headerSize+programSize+len(code))
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[24:], baseAddress+headerSize+programSize)
	binary.LittleEndian.PutUint64(data[32:], headerSize)
	binary.LittleEndian.PutUint16(data[52:], headerSize)
	binary.LittleEndian.PutUint16(data[54:], programSize)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint32(data[headerSize:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(data[headerSize+4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(data[headerSize+16:], baseAddress)
	binary.LittleEndian.PutUint64(data[headerSize+24:], baseAddress)
	binary.LittleEndian.PutUint64(data[headerSize+32:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[headerSize+40:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[headerSize+48:], 0x1000)
	copy(data[headerSize+programSize:], code)
	return data
}

func mustOpenDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), path)
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	})
	return directory
}
