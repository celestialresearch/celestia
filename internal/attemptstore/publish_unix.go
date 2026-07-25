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

//go:build !windows

package attemptstore

import (
	"os"
	"syscall"
)

func publishFile(source, target, directory string) error {
	if err := os.Link(source, target); err != nil {
		if os.IsExist(err) {
			return ErrDuplicate
		}
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()
	handle, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func publishDirectory(source, target, directory string) error {
	if err := os.Rename(source, target); err != nil {
		if os.IsExist(err) {
			return ErrDuplicate
		}
		return err
	}
	return syncDirectory(directory)
}

func secureEvidenceTree(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || pathIsLinked(path, info) {
		return ErrCorrupt
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && int64(stat.Uid) != int64(os.Geteuid()) {
		return ErrCorrupt
	}
	if info.Mode().Perm() != 0o700 {
		return ErrCorrupt
	}
	return nil
}

func pathIsLinked(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func syncDirectory(directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()
	handle, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
