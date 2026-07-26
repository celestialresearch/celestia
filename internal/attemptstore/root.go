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

package attemptstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareEvidenceRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: evidence root", ErrInvalid)
	}
	clean, err := resolveEvidenceRoot(root)
	if err != nil {
		return "", fmt.Errorf("resolve evidence root: %w", err)
	}
	if err := rejectLinkedAncestors(clean); err != nil {
		return "", fmt.Errorf("inspect evidence root: %w", err)
	}
	if _, err := lstatEvidencePath(clean); err == nil {
		return clean, adoptEvidenceRoot(clean)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect evidence root: %w", err)
	}
	return clean, createEvidenceRoot(clean)
}

func adoptEvidenceRoot(path string) error {
	if err := secureEvidenceTree(path); err != nil {
		return fmt.Errorf("inspect evidence root: %w", err)
	}
	return nil
}

func createEvidenceRoot(path string) error {
	parent := filepath.Dir(path)
	info, err := lstatEvidencePath(parent)
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
	if err := secureEvidenceParent(parent); err != nil {
		return fmt.Errorf("inspect evidence root parent: %w", err)
	}
	if err := createEvidenceDirectory(path); err != nil {
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
	for _, directory := range []string{
		filepath.Join(root, attemptsDirectory),
		filepath.Join(root, attemptsDirectory, pendingDirectory),
	} {
		if err := ensureEvidenceDirectory(directory); err != nil {
			return fmt.Errorf("prepare evidence tree: %w", err)
		}
	}
	return nil
}

func validateEvidenceDirectories(root string) error {
	for _, directory := range []string{
		root,
		filepath.Join(root, attemptsDirectory),
		filepath.Join(root, attemptsDirectory, pendingDirectory),
		filepath.Join(root, locksDirectory),
	} {
		if err := secureEvidenceTree(directory); err != nil {
			return err
		}
	}
	return nil
}

func ensureEvidenceDirectory(path string) error {
	if _, err := lstatEvidencePath(path); errors.Is(err, os.ErrNotExist) {
		return createEvidenceDirectory(path)
	} else if err != nil {
		return err
	}
	return secureEvidenceTree(path)
}

func createLockDirectory(root string) (bool, error) {
	err := createEvidenceDirectory(filepath.Join(root, locksDirectory))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	return false, err
}
