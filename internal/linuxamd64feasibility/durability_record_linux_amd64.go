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
	"bytes"
	"errors"
	"io"

	"golang.org/x/sys/unix"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	size   int64
}

type fixtureFile struct {
	name     string
	identity fileIdentity
}

type ownedFixture struct {
	root      durabilityRoot
	fd        int
	name      string
	identity  fileIdentity
	temporary *fixtureFile
	final     *fixtureFile
}

func (root durabilityRoot) createFixture() (ownedFixture, error) {
	for range cgroupLeafAttempts {
		name, err := durabilityName()
		if err != nil {
			return ownedFixture{}, err
		}
		if err := unix.Mkdirat(root.fd, name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return ownedFixture{}, err
		}
		fixture, err := openFixture(root, name)
		if err != nil {
			removeErr := unix.Unlinkat(root.fd, name, unix.AT_REMOVEDIR)
			return ownedFixture{}, errors.Join(err, removeErr, unix.Fsync(root.fd))
		}
		if err := unix.Fsync(root.fd); err != nil {
			return ownedFixture{}, errors.Join(err, fixture.remove())
		}
		return fixture, nil
	}
	return ownedFixture{}, unix.EEXIST
}

func openFixture(root durabilityRoot, name string) (ownedFixture, error) {
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ownedFixture{}, err
	}
	identity, err := fixtureDirectoryIdentity(fd, root.euid, root.device)
	if err != nil {
		return ownedFixture{}, errors.Join(err, unix.Close(fd))
	}
	fixture := ownedFixture{root: root, fd: fd, name: name, identity: identity}
	if err := fixture.namedIdentity(); err != nil {
		return ownedFixture{}, errors.Join(err, unix.Close(fd))
	}
	return fixture, nil
}

func fixtureDirectoryIdentity(fd int, euid uint32, device uint64) (fileIdentity, error) {
	var information unix.Stat_t
	if err := unix.Fstat(fd, &information); err != nil {
		return fileIdentity{}, err
	}
	if information.Mode&unix.S_IFMT != unix.S_IFDIR || information.Uid != euid ||
		information.Mode&0o077 != 0 || information.Dev != device || information.Nlink != 2 {
		return fileIdentity{}, errDurabilityRootUnsafe
	}
	return fileIdentity{device: information.Dev, inode: information.Ino}, nil
}

func (fixture *ownedFixture) writeTemporary() error {
	fd, err := unix.Openat(
		fixture.fd,
		durabilityTemporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return err
	}
	identity, err := fixtureFileIdentity(fd, fixture.root.euid, fixture.root.device)
	if err != nil {
		return errors.Join(err, unix.Close(fd))
	}
	fixture.temporary = &fixtureFile{name: durabilityTemporary, identity: identity}
	data := []byte(durabilityRecordData)
	if err := writeAll(func(data []byte) (int, error) { return unix.Write(fd, data) }, data); err != nil {
		return errors.Join(err, unix.Close(fd))
	}
	if err := unix.Fsync(fd); err != nil {
		return errors.Join(err, unix.Close(fd))
	}
	identity, err = fixtureFileIdentity(fd, fixture.root.euid, fixture.root.device)
	closeErr := unix.Close(fd)
	if err != nil {
		return errors.Join(err, closeErr)
	}
	if identity.size != int64(len(data)) {
		return errors.Join(errDurabilityRootUnsafe, closeErr)
	}
	fixture.temporary.identity = identity
	return closeErr
}

func fixtureFileIdentity(fd int, euid uint32, device uint64) (fileIdentity, error) {
	var information unix.Stat_t
	if err := unix.Fstat(fd, &information); err != nil {
		return fileIdentity{}, err
	}
	if information.Mode&unix.S_IFMT != unix.S_IFREG || information.Uid != euid ||
		information.Mode&0o077 != 0 || information.Nlink != 1 || information.Dev != device {
		return fileIdentity{}, errDurabilityRootUnsafe
	}
	return fileIdentity{device: information.Dev, inode: information.Ino, size: information.Size}, nil
}

func writeAll(write func([]byte) (int, error), data []byte) error {
	for len(data) > 0 {
		count, err := write(data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if count <= 0 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func (fixture *ownedFixture) publish() error {
	if fixture.temporary == nil || fixture.final != nil {
		return errDurabilityRootUnsafe
	}
	if err := fixture.matchFile(*fixture.temporary); err != nil {
		return err
	}
	if err := unix.Renameat2(fixture.fd, fixture.temporary.name, fixture.fd, durabilityRecord, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	fixture.final = &fixtureFile{name: durabilityRecord, identity: fixture.temporary.identity}
	fixture.temporary = nil
	if err := unix.Fsync(fixture.fd); err != nil {
		return err
	}
	return fixture.matchFile(*fixture.final)
}

func (fixture *ownedFixture) verify() error {
	if fixture.final == nil {
		return errDurabilityRootUnsafe
	}
	fd, err := unix.Openat(fixture.fd, fixture.final.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	identity, identityErr := fixtureFileIdentity(fd, fixture.root.euid, fixture.root.device)
	if identityErr != nil || identity != fixture.final.identity {
		return errors.Join(identityErr, unix.Close(fd), errDurabilityRootUnsafe)
	}
	data, readErr := readDurabilityFile(fd, len(durabilityRecordData))
	closeErr := unix.Close(fd)
	if readErr != nil || closeErr != nil || !bytes.Equal(data, []byte(durabilityRecordData)) {
		return errors.Join(readErr, closeErr, errDurabilityRootUnsafe)
	}
	return nil
}

func readDurabilityFile(fd, limit int) ([]byte, error) {
	file := durabilityFile{fd: fd}
	data, err := io.ReadAll(io.LimitReader(&file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, errors.Join(err, io.ErrShortBuffer)
	}
	return data, nil
}

type durabilityFile struct {
	fd int
}

func (file *durabilityFile) Read(data []byte) (int, error) {
	for {
		count, err := unix.Read(file.fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return count, err
	}
}
