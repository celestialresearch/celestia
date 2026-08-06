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

func openStaticFixture(root, relative string) (*os.File, fixtureObservation, error) {
	if !validFixturePath(root, relative) {
		return nil, fixtureObservation{}, unix.EINVAL
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fixtureObservation{}, err
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
		return nil, fixtureObservation{}, err
	}
	file := os.NewFile(uintptr(fd), relative)
	identity, err := staticFixtureIdentity(file)
	if err != nil {
		return nil, fixtureObservation{}, errors.Join(err, file.Close())
	}
	return file, identity, nil
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

func staticFixtureIdentity(file *os.File) (fixtureObservation, error) {
	var information unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &information); err != nil {
		return fixtureObservation{}, err
	}
	euid := os.Geteuid()
	if euid < 0 || uint64(euid) > math.MaxUint32 || !validFixtureStat(information, uint32(euid)) {
		return fixtureObservation{}, errors.New("unsafe fixture file")
	}
	fixtureType, err := staticELFType(file)
	if err != nil {
		return fixtureObservation{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, information.Size)); err != nil {
		return fixtureObservation{}, err
	}
	return fixtureObservation{
		SHA256: hex.EncodeToString(hash.Sum(nil)), ELFMachine: "x86_64",
		ELFType: fixtureType, PTInterp: false,
		Device: information.Dev, Inode: information.Ino,
	}, nil
}

func validFixtureStat(information unix.Stat_t, euid uint32) bool {
	return information.Mode&unix.S_IFMT == unix.S_IFREG && information.Uid == euid &&
		information.Mode&0o022 == 0 && information.Mode&0o111 != 0 && information.Nlink == 1 &&
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
