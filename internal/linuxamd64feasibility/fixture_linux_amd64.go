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
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxFixtureBytes = 16 << 20

const fixtureSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

type fixtureIdentity struct {
	SHA256     string
	ELFMachine string
	ELFType    string
	PTInterp   bool
	Device     uint64
	Inode      uint64
}

func openStaticFixture(root, relative string) (*os.File, fixtureIdentity, error) {
	if !validFixturePath(root, relative) {
		return nil, fixtureIdentity{}, unix.EINVAL
	}
	rootFD, err := openFixtureRoot(root)
	if err != nil {
		return nil, fixtureIdentity{}, err
	}
	how := &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	fd, openErr := unix.Openat2(rootFD, relative, how)
	if err := errors.Join(openErr, unix.Close(rootFD)); err != nil {
		if fd >= 0 {
			err = errors.Join(err, unix.Close(fd))
		}
		return nil, fixtureIdentity{}, err
	}
	source := os.NewFile(uintptr(fd), relative)
	snapshot, snapshotErr := sealedFixtureSnapshot(source)
	if err := errors.Join(snapshotErr, source.Close()); err != nil {
		if snapshot != nil {
			err = errors.Join(err, snapshot.Close())
		}
		return nil, fixtureIdentity{}, err
	}
	identity, err := staticFixtureIdentity(snapshot)
	if err != nil {
		return nil, fixtureIdentity{}, errors.Join(err, snapshot.Close())
	}
	return snapshot, identity, nil
}

func sealedFixtureSnapshot(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, errors.New("unsafe fixture file")
	}
	var information unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &information); err != nil {
		return nil, err
	}
	euid := os.Geteuid()
	if euid < 0 || uint64(euid) > math.MaxUint32 || !validFixtureStat(information, uint32(euid)) {
		return nil, errors.New("unsafe fixture file")
	}
	fd, err := unix.MemfdCreate("celestia-hostile-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	snapshot := os.NewFile(uintptr(fd), "celestia-hostile-fixture")
	count, copyErr := io.Copy(snapshot, io.NewSectionReader(source, 0, information.Size))
	modeErr := unix.Fchmod(fd, 0o500)
	_, sealErr := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, fixtureSeals)
	if err := errors.Join(copyErr, modeErr, sealErr); err != nil || count != information.Size {
		if count != information.Size {
			err = errors.Join(err, io.ErrUnexpectedEOF)
		}
		return nil, errors.Join(err, snapshot.Close())
	}
	return snapshot, nil
}

func openFixtureRoot(root string) (int, error) {
	parts, err := durabilityRootParts(root)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range parts {
		next, openErr := unix.Openat(fd, part,
			unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(fd)
		if err := errors.Join(openErr, closeErr); err != nil {
			if openErr == nil {
				err = errors.Join(err, unix.Close(next))
			}
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func validFixturePath(root, relative string) bool {
	if !filepath.IsAbs(root) || relative == "" || filepath.IsAbs(relative) ||
		strings.ContainsRune(root, 0) || strings.ContainsRune(relative, 0) {
		return false
	}
	clean := filepath.Clean(relative)
	return clean == relative && clean != "." && clean != ".." &&
		!strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func staticFixtureIdentity(file *os.File) (fixtureIdentity, error) {
	var information unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &information); err != nil {
		return fixtureIdentity{}, err
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&fixtureSeals != fixtureSeals ||
		information.Mode&unix.S_IFMT != unix.S_IFREG || information.Mode&0o777 != 0o500 ||
		information.Size <= 0 || information.Size > maxFixtureBytes {
		return fixtureIdentity{}, errors.New("unsafe fixture file")
	}
	fixtureType, err := staticELFType(file)
	if err != nil {
		return fixtureIdentity{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, information.Size)); err != nil {
		return fixtureIdentity{}, err
	}
	return fixtureIdentity{
		SHA256: hex.EncodeToString(hash.Sum(nil)), ELFMachine: "x86_64",
		ELFType: fixtureType, PTInterp: false,
		Device: information.Dev, Inode: information.Ino,
	}, nil
}

func validFixtureStat(information unix.Stat_t, euid uint32) bool {
	return information.Mode&unix.S_IFMT == unix.S_IFREG && information.Uid == euid &&
		information.Mode&0o022 == 0 && information.Mode&0o100 != 0 && information.Nlink == 1 &&
		information.Size > 0 && information.Size <= maxFixtureBytes
}

func staticELFType(file *os.File) (string, error) {
	image, err := elf.NewFile(file)
	if err != nil {
		return "", err
	}
	if image.Class != elf.ELFCLASS64 || image.Machine != elf.EM_X86_64 ||
		(image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN) || hasInterpreter(image) ||
		!hasExecutableLoad(image) {
		return "", errors.New("fixture is not a static AMD64 executable")
	}
	return image.Type.String(), nil
}

func hasExecutableLoad(image *elf.File) bool {
	for _, program := range image.Progs {
		if program.Type == elf.PT_LOAD && program.Flags&elf.PF_X != 0 {
			return true
		}
	}
	return false
}

func hasInterpreter(image *elf.File) bool {
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return true
		}
	}
	return false
}
