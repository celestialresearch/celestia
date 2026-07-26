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
	"slices"
)

func (store *Store) attemptsPath() string {
	return filepath.Join(store.root, attemptsDirectory)
}

func (store *Store) pendingRoot() string {
	return filepath.Join(store.attemptsPath(), pendingDirectory)
}

func (store *Store) pendingPath(attemptID string) string {
	return filepath.Join(store.pendingRoot(), attemptID)
}

func (store *Store) finalPath(attemptID string) string {
	return filepath.Join(store.attemptsPath(), attemptID)
}

func (store *Store) prepareAttemptDirectories(
	attemptID string,
	createDirectory func(string) error,
) (string, string, error) {
	if exists, err := pathExists(store.finalPath(attemptID)); err != nil {
		return "", "", fmt.Errorf("inspect published attempt: %w", err)
	} else if exists {
		return "", "", ErrDuplicate
	}
	pendingPath := store.pendingPath(attemptID)
	if err := createDirectory(pendingPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", "", ErrDuplicate
		}
		return "", "", fmt.Errorf("create attempt: %w", err)
	}
	path := filepath.Join(pendingPath, bundleDirectory)
	if err := createDirectory(path); err != nil {
		return pendingPath, "", fmt.Errorf("create attempt bundle: %w", err)
	}
	return pendingPath, path, nil
}

func removeStagedAttempt(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("roll back staged attempt: %w", err)
	}
	return nil
}

func (store *Store) rollbackStage(
	attemptID string,
	pendingPath string,
	markerCreated bool,
	removePending func(string) error,
) error {
	if pendingPath != "" {
		if err := removePending(pendingPath); err != nil {
			return err
		}
	}
	if markerCreated {
		return store.removeOwnershipMarker(attemptID)
	}
	return nil
}

func canonicalEvidenceRoot(path string) (string, error) {
	clean := filepath.Clean(path)
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || pathIsLinked(clean, info) {
			return "", ErrCorrupt
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	existing := clean
	var suffix []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", os.ErrNotExist
		}
		suffix = append(suffix, filepath.Base(existing))
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	for _, component := range slices.Backward(suffix) {
		resolved = filepath.Join(resolved, component)
	}
	return resolved, nil
}

func pathExists(path string) (bool, error) {
	if err := rejectLinkedAncestors(path); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || pathIsLinked(path, info) {
		return false, ErrCorrupt
	}
	return true, nil
}

func publishPendingDirectory(source, target, parent string) (string, error) {
	if exists, err := pathExists(target); err != nil {
		return "", err
	} else if exists {
		return "", ErrDuplicate
	}
	if err := publishDirectory(source, target, parent); err != nil {
		return "", fmt.Errorf("publish attempt directory: %w", err)
	}
	return target, nil
}

func rejectLinkedAncestors(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || pathIsLinked(current, info) {
				return ErrCorrupt
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}
