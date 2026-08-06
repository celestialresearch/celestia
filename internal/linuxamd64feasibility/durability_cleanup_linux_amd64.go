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

	"golang.org/x/sys/unix"
)

func (fixture *ownedFixture) remove() error {
	var result error
	if fixture.temporary != nil {
		if err := fixture.removeFile(*fixture.temporary); err != nil {
			result = errors.Join(result, err)
		} else {
			fixture.temporary = nil
		}
	}
	if fixture.final != nil {
		if err := fixture.removeFile(*fixture.final); err != nil {
			result = errors.Join(result, err)
		} else {
			fixture.final = nil
		}
	}
	if err := unix.Fsync(fixture.fd); err != nil {
		result = errors.Join(result, err)
	}
	if err := fixture.namedIdentity(); err != nil {
		result = errors.Join(result, err)
		return errors.Join(result, fixture.close())
	}
	if fixture.temporary != nil || fixture.final != nil {
		return errors.Join(result, fixture.close())
	}
	result = errors.Join(result, fixture.close())
	if err := unix.Unlinkat(fixture.root.fd, fixture.name, unix.AT_REMOVEDIR); err != nil {
		return errors.Join(result, err)
	}
	return errors.Join(result, unix.Fsync(fixture.root.fd))
}

func (fixture *ownedFixture) close() error {
	if fixture.fd < 0 {
		return nil
	}
	err := unix.Close(fixture.fd)
	fixture.fd = -1
	return err
}

func (fixture *ownedFixture) removeFile(file fixtureFile) error {
	if err := fixture.matchFile(file); err != nil {
		return err
	}
	return unix.Unlinkat(fixture.fd, file.name, 0)
}

func (fixture *ownedFixture) namedIdentity() error {
	var named unix.Stat_t
	if err := unix.Fstatat(fixture.root.fd, fixture.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if named.Dev != fixture.identity.device || named.Ino != fixture.identity.inode {
		return errDurabilityRootUnsafe
	}
	return nil
}

func (fixture *ownedFixture) matchFile(file fixtureFile) error {
	var information unix.Stat_t
	if err := unix.Fstatat(fixture.fd, file.name, &information, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if information.Mode&unix.S_IFMT != unix.S_IFREG || information.Uid != fixture.root.euid ||
		information.Mode&0o077 != 0 || information.Nlink != 1 || information.Dev != file.identity.device ||
		information.Ino != file.identity.inode || information.Size != file.identity.size {
		return errDurabilityRootUnsafe
	}
	return nil
}
