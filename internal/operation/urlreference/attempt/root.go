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

//go:build windows || (linux && amd64)

package attemptstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareEvidenceRoot(root string) (string, error) {
	return prepareEvidenceRootWith(
		root,
		resolveEvidenceRoot,
		rejectLinkedAncestors,
		lstatEvidencePath,
		adoptEvidenceRoot,
		createEvidenceRoot,
	)
}

func prepareEvidenceRootWith(
	root string,
	resolve func(string) (string, error),
	rejectLinks func(string) error,
	lstat func(string) (os.FileInfo, error),
	adopt func(string) error,
	create func(string) error,
) (string, error) {
	if !validEvidenceRootPath(root) {
		return "", fmt.Errorf("%w: evidence root", ErrInvalid)
	}
	clean, err := resolve(root)
	if err != nil {
		return "", fmt.Errorf("resolve evidence root: %w", err)
	}
	if err := rejectLinks(clean); err != nil {
		return "", fmt.Errorf("inspect evidence root: %w", err)
	}
	if _, err := lstat(clean); err == nil {
		return clean, adopt(clean)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect evidence root: %w", err)
	}
	return clean, create(clean)
}

func adoptEvidenceRoot(path string) error {
	if err := secureEvidenceTree(path); err != nil {
		return fmt.Errorf("inspect evidence root: %w", err)
	}
	return nil
}

func createEvidenceRoot(path string) error {
	return createEvidenceRootWith(
		path,
		lstatEvidencePath,
		secureEvidenceParent,
		createEvidenceDirectory,
	)
}

func createEvidenceRootWith(
	path string,
	lstat func(string) (os.FileInfo, error),
	secureParent func(string) error,
	create func(string) error,
) error {
	parent := filepath.Dir(path)
	info, err := lstat(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: evidence root parent must exist", ErrInvalid)
		}
		return fmt.Errorf("inspect evidence root parent: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		pathIsLinked(parent, info) {
		return fmt.Errorf("%w: evidence root parent", ErrCorrupt)
	}
	if err := secureParent(parent); err != nil {
		return fmt.Errorf("inspect evidence root parent: %w", err)
	}
	if err := create(path); err != nil {
		return fmt.Errorf("create evidence root: %w", err)
	}
	return nil
}

func lstatEvidencePath(path string) (os.FileInfo, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	info, statErr := root.Lstat(filepath.Base(path))
	return info, errors.Join(statErr, root.Close())
}

func prepareEvidenceDirectories(root string) error {
	return prepareEvidenceDirectoriesWith(root, ensureEvidenceDirectory)
}

func prepareEvidenceDirectoriesWith(
	root string,
	ensure func(string) error,
) error {
	for _, directory := range []string{
		filepath.Join(root, attemptsDirectory),
		filepath.Join(root, attemptsDirectory, pendingDirectory),
	} {
		if err := ensure(directory); err != nil {
			return fmt.Errorf("prepare evidence tree: %w", err)
		}
	}
	return nil
}

func validateEvidenceDirectories(root string) error {
	return validateEvidenceDirectoriesWith(root, secureEvidenceTree)
}

func validateEvidenceDirectoriesWith(
	root string,
	secure func(string) error,
) error {
	for _, directory := range []string{
		root,
		filepath.Join(root, attemptsDirectory),
		filepath.Join(root, attemptsDirectory, pendingDirectory),
		filepath.Join(root, locksDirectory),
	} {
		if err := secure(directory); err != nil {
			return err
		}
	}
	return nil
}

func ensureEvidenceDirectory(path string) error {
	return ensureEvidenceDirectoryWith(
		path,
		lstatEvidencePath,
		createEvidenceDirectory,
		secureEvidenceTree,
	)
}

func ensureEvidenceDirectoryWith(
	path string,
	lstat func(string) (os.FileInfo, error),
	create func(string) error,
	secure func(string) error,
) error {
	if _, err := lstat(path); errors.Is(err, os.ErrNotExist) {
		return create(path)
	} else if err != nil {
		return err
	}
	return secure(path)
}

func createLockDirectory(root string) (bool, error) {
	return createLockDirectoryWith(root, createEvidenceDirectory)
}

func createLockDirectoryWith(
	root string,
	create func(string) error,
) (bool, error) {
	err := create(filepath.Join(root, locksDirectory))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	return false, err
}
