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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package attemptstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func publishFile(source, target, directory string) (err error) {
	if err := os.Link(source, target); err != nil {
		if os.IsExist(err) {
			return ErrDuplicate
		}
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func publishDirectory(source, target, directory string) error {
	if err := os.Rename(source, target); err != nil {
		if os.IsExist(err) {
			return ErrDuplicate
		}
		return err
	}
	return errors.Join(
		syncDirectory(directory),
		syncDirectory(filepath.Dir(source)),
	)
}

func secureEvidenceTree(path string) error {
	info, err := lstatEvidencePath(path)
	if err != nil {
		return err
	}
	return validateEvidenceDirectory(path, info)
}

func validateEvidenceDirectory(path string, info os.FileInfo) error {
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

func secureEvidenceFile(path string) error {
	info, err := lstatEvidencePath(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		int64(stat.Uid) != int64(os.Geteuid()) ||
		stat.Nlink != 1 ||
		info.Mode().Perm() != 0o600 {
		return ErrCorrupt
	}
	return nil
}

func createEvidenceDirectory(path string) error {
	parent := filepath.Dir(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	if err := root.Mkdir(name, 0o700); err != nil {
		return errors.Join(err, root.Close())
	}
	info, statErr := root.Lstat(name)
	closeErr := root.Close()
	if err := errors.Join(statErr, closeErr); err != nil {
		return errors.Join(err, removeCreatedDirectory(path, parent))
	}
	if err := validateEvidenceDirectory(path, info); err != nil {
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
	closeErr := root.Close()
	return errors.Join(removeErr, closeErr, syncDirectory(parent))
}

func pathIsLinked(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func syncDirectory(directory string) (err error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, root.Close())
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

func confirmPublication(directory string) error {
	return syncDirectory(directory)
}

func repairInterruptedRecords(path string) (err error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	removals, err := interruptedRecordRemovals(root, entries)
	if err != nil {
		return err
	}
	if err := removeInterruptedRecords(root, path, removals); err != nil {
		return err
	}
	return verifyRepairedRecords(root, path)
}

func interruptedRecordRemovals(
	root *os.Root,
	entries []os.DirEntry,
) ([]string, error) {
	var removals []string
	for _, name := range recordNames() {
		recordRemovals, err := interruptedRecordRemovalsFor(root, entries, name)
		if err != nil {
			return nil, err
		}
		removals = append(removals, recordRemovals...)
	}
	return removals, nil
}

func interruptedRecordRemovalsFor(
	root *os.Root,
	entries []os.DirEntry,
	name string,
) ([]string, error) {
	target, present, err := interruptedTarget(root, name)
	if err != nil {
		return nil, err
	}
	removals, linked, err := interruptedTemporaries(root, entries, name, target, present)
	if err != nil {
		return nil, err
	}
	if !present {
		return removals, nil
	}
	stat := target.Sys().(*syscall.Stat_t)
	if stat.Nlink == 2 && linked != 1 || stat.Nlink == 1 && linked != 0 {
		return nil, ErrCorrupt
	}
	return removals, nil
}

func interruptedTarget(root *os.Root, name string) (os.FileInfo, bool, error) {
	target, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !validInterruptedRecord(target) {
		return nil, false, ErrCorrupt
	}
	return target, true, nil
}

func interruptedTemporaries(
	root *os.Root,
	entries []os.DirEntry,
	name string,
	target os.FileInfo,
	targetPresent bool,
) ([]string, int, error) {
	var removals []string
	var linked int
	for _, entry := range entries {
		if !temporaryRecordName(name, entry.Name()) {
			continue
		}
		info, err := root.Lstat(entry.Name())
		if err != nil || !validInterruptedRecord(info) {
			return nil, 0, ErrCorrupt
		}
		stat := info.Sys().(*syscall.Stat_t)
		sameTarget := targetPresent && os.SameFile(target, info)
		if stat.Nlink == 2 && !sameTarget {
			return nil, 0, ErrCorrupt
		}
		if sameTarget {
			linked++
		}
		removals = append(removals, entry.Name())
	}
	return removals, linked, nil
}

func removeInterruptedRecords(root *os.Root, path string, removals []string) error {
	if len(removals) == 0 {
		return nil
	}
	for _, name := range removals {
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	if err := syncDirectory(path); err != nil {
		return err
	}
	return nil
}

func verifyRepairedRecords(root *os.Root, path string) error {
	for _, name := range recordNames() {
		if _, err := root.Lstat(name); err == nil {
			if err := secureEvidenceFile(filepath.Join(path, name)); err != nil {
				return fmt.Errorf("verify repaired record %s: %w", name, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func validInterruptedRecord(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 &&
		int64(stat.Uid) == int64(os.Geteuid()) &&
		(stat.Nlink == 1 || stat.Nlink == 2) &&
		info.Mode().Perm() == 0o600
}
