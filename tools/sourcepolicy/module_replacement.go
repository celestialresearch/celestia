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

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

func rejectExternalModuleReplacements(
	paths []string,
	readFile func(string) ([]byte, error),
) error {
	repositoryRoot, err := filepath.Abs(".")
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	for _, path := range paths {
		if filepath.Base(path) != "go.mod" {
			continue
		}
		source, err := readFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		module, err := modfile.Parse(path, source, nil)
		if err != nil {
			return fmt.Errorf("%s: parse Go module: %w", path, err)
		}
		for _, replacement := range module.Replace {
			escapes, err := moduleReplacementEscapes(
				path,
				replacement,
				repositoryRoot,
			)
			if err != nil {
				return err
			}
			if escapes {
				return fmt.Errorf(
					"%s: Go module replacement escapes the repository",
					path,
				)
			}
		}
	}
	return nil
}

func moduleReplacementEscapes(
	modulePath string,
	replacement *modfile.Replace,
	repositoryRoot string,
) (bool, error) {
	if replacement.New.Version != "" || replacement.New.Path == "" {
		return false, nil
	}
	target := replacement.New.Path
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(modulePath), target)
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return false, fmt.Errorf(
			"%s: resolve Go module replacement: %w",
			modulePath,
			err,
		)
	}
	relative, err := filepath.Rel(repositoryRoot, absolute)
	if err != nil {
		return false, fmt.Errorf(
			"%s: compare Go module replacement: %w",
			modulePath,
			err,
		)
	}
	if pathEscapesRoot(relative) {
		return true, nil
	}
	linked, err := replacementPathLinked(repositoryRoot, absolute)
	if err != nil {
		return false, fmt.Errorf(
			"%s: inspect Go module replacement path: %w",
			modulePath,
			err,
		)
	}
	if linked {
		return true, nil
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return false, fmt.Errorf(
			"%s: resolve physical Go module replacement: %w",
			modulePath,
			err,
		)
	}
	physicalRelative, err := filepath.Rel(repositoryRoot, resolved)
	if err != nil {
		return false, fmt.Errorf(
			"%s: compare physical Go module replacement: %w",
			modulePath,
			err,
		)
	}
	return pathEscapesRoot(physicalRelative), nil
}

func pathEscapesRoot(relative string) bool {
	return relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
