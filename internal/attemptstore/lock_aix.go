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

//go:build aix

package attemptstore

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var errLockHeld = errors.New("attempt lock held")

func openAttemptLockFile(root *os.Root, _ string, name string, create bool) (*os.File, error) {
	file, err := root.OpenFile(name, os.O_RDWR, 0o600)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open attempt lock: %w", err)
	}
	if !create {
		return nil, ErrCorrupt
	}
	file, err = root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return root.OpenFile(name, os.O_RDWR, 0o600)
	}
	if err != nil {
		return nil, fmt.Errorf("create attempt lock: %w", err)
	}
	return file, nil
}

func lockAttemptFile(file *os.File) error {
	lock := unix.Flock_t{Type: unix.F_WRLCK}
	err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EAGAIN) {
		return errLockHeld
	}
	return err
}

func unlockAttemptFile(file *os.File) error {
	lock := unix.Flock_t{Type: unix.F_UNLCK}
	return unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
}

func secureLockFile(_ *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		int64(stat.Uid) != int64(os.Geteuid()) ||
		stat.Nlink != 1 ||
		info.Mode().Perm() != 0o600 {
		return ErrCorrupt
	}
	return nil
}

func syncAttemptLockDirectory(directory string) error {
	return syncDirectory(directory)
}
