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
	"syscall"

	"celestia.research/celestia/internal/linuxamd64feasibility"
)

func validEvidenceRootPath(path string) bool {
	return path != "" && len(path) <= 4096 && filepath.IsAbs(path) &&
		filepath.Clean(path) == path && path != string(filepath.Separator)
}

func secureEvidenceParent(path string) error {
	info, err := lstatEvidencePath(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		int64(stat.Uid) != int64(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return ErrCorrupt
	}
	return validEvidenceFilesystem(path)
}

func validEvidenceFilesystem(path string) error {
	filesystem, err := linuxamd64feasibility.EvidenceFilesystem(path)
	if err != nil {
		return err
	}
	if !validEvidenceFilesystemType(filesystem) {
		return ErrCorrupt
	}
	return nil
}

func validEvidenceFilesystemType(value string) bool {
	return value == "ext4" || value == "xfs"
}

func secureEvidenceTree(path string) error {
	info, err := lstatEvidencePath(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		int64(stat.Uid) != int64(os.Geteuid()) || info.Mode().Perm() != 0o700 {
		return ErrCorrupt
	}
	return validEvidenceFilesystem(path)
}

func secureEvidenceFile(path string) error {
	info, err := lstatEvidencePath(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		int64(stat.Uid) != int64(os.Geteuid()) || stat.Nlink != 1 ||
		info.Mode().Perm() != 0o600 {
		return ErrCorrupt
	}
	return validEvidenceFilesystem(path)
}

func createEvidenceDirectory(path string) error {
	parent := filepath.Dir(path)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	createErr := root.Mkdir(name, 0o700)
	closeErr := root.Close()
	if err := errors.Join(createErr, closeErr); err != nil {
		if createErr == nil {
			return errors.Join(err, removeCreatedDirectory(path, parent))
		}
		return err
	}
	if err := secureEvidenceTree(path); err != nil {
		return errors.Join(err, removeCreatedDirectory(path, parent))
	}
	if err := syncDirectory(parent); err != nil {
		return errors.Join(err, removeCreatedDirectory(path, parent))
	}
	return nil
}

func removeCreatedDirectory(path, parent string) error {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	removeErr := root.Remove(filepath.Base(path))
	return errors.Join(removeErr, root.Close(), syncDirectory(parent))
}

func pathIsLinked(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
