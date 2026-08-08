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

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishFile(source, target, directory string) (err error) {
	if filepath.Dir(source) != directory || filepath.Dir(target) != directory {
		return ErrCorrupt
	}
	parent, err := openDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(parent)) }()
	err = unix.Renameat2(parent, filepath.Base(source), parent,
		filepath.Base(target), unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	return syncFD(parent)
}

func publishDirectory(source, target, _ string) (err error) {
	sourceParent, err := openDirectory(filepath.Dir(source))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(sourceParent)) }()
	targetParent, err := openDirectory(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(targetParent)) }()
	err = unix.Renameat2(sourceParent, filepath.Base(source), targetParent,
		filepath.Base(target), unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	return errors.Join(syncFD(targetParent), syncFD(sourceParent))
}

func openDirectory(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func syncFD(fd int) error {
	return unix.Fsync(fd)
}

func syncDirectory(path string) error {
	fd, err := openDirectory(path)
	if err != nil {
		return err
	}
	return errors.Join(syncFD(fd), unix.Close(fd))
}

func confirmPublication(directory string) error {
	return syncDirectory(directory)
}

func repairInterruptedRecords(path string) (err error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !recordTemporary(entry.Name()) {
			continue
		}
		if err := secureEvidenceFile(filepath.Join(path, entry.Name())); err != nil {
			return ErrCorrupt
		}
		if err := root.Remove(entry.Name()); err != nil {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return confirmPublication(path)
}

func recordTemporary(candidate string) bool {
	for _, record := range recordNames() {
		if temporaryRecordName(record, candidate) {
			return true
		}
	}
	return false
}
