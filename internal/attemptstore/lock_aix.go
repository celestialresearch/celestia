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
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var errLockHeld = errors.New("attempt lock held")

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
