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
)

func policyFindings(
	files []string,
	mode string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	var findings []string
	if mode == modeSuppressions {
		findings = append(
			findings,
			cargoWorkspaceInventoryFindings(files, readFile)...,
		)
	}
	if mode == modeTestSkips {
		goFindings, err := goPackageSkipFindings(files, readFile)
		if err != nil {
			return nil, err
		}
		findings = append(findings, goFindings...)
	}
	for _, path := range files {
		findings = append(findings, scanFile(path, mode, readFile)...)
	}
	return findings, nil
}

func scanFile(
	path, mode string,
	readFile func(string) ([]byte, error),
) []string {
	if finding := alternateGolangciFinding(path, mode); finding != "" {
		return []string{finding}
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		if mode != modeSuppressions {
			return nil
		}
		return readFindings(path, readFile, goSuppressionFindings)
	case ".rs":
		return readFindings(path, readFile, func(path string, source []byte) []string {
			return rustFindings(path, source, mode)
		})
	case ".toml", "":
		return tomlFindings(path, mode, readFile)
	case ".sh", ".bash":
		if mode != modeSuppressions {
			return nil
		}
		return readFindings(path, readFile, shellSuppressionFindings)
	case ".ps1":
		return nil
	case ".yml", ".yaml":
		if mode == modeSuppressions &&
			filepath.Base(path) == ".golangci.yml" {
			return readFindings(path, readFile, golangciConfigFindings)
		}
		return nil
	}
	return nil
}

func tomlFindings(
	path, mode string,
	readFile func(string) ([]byte, error),
) []string {
	if mode != modeSuppressions {
		return nil
	}
	switch {
	case filepath.Base(path) == "Cargo.toml":
		return readFindings(path, readFile, cargoLintFindings)
	case (filepath.Base(path) == "config.toml" ||
		filepath.Base(path) == "config") &&
		filepath.Base(filepath.Dir(path)) == ".cargo":
		return readFindings(path, readFile, cargoConfigFindings)
	default:
		return nil
	}
}

func alternateGolangciFinding(path, mode string) string {
	if mode != modeSuppressions {
		return ""
	}
	original := filepath.Base(path)
	switch strings.ToLower(original) {
	case ".golangci.yml":
		if original == ".golangci.yml" {
			return ""
		}
	case ".golangci.yaml", ".golangci.toml", ".golangci.json":
	default:
		return ""
	}
	return fmt.Sprintf(
		"%s: alternate golangci-lint configurations are prohibited",
		path,
	)
}

func readFindings(
	path string,
	readFile func(string) ([]byte, error),
	scan func(string, []byte) []string,
) []string {
	source, err := readFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", path, err)}
	}
	return scan(path, source)
}
