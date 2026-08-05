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
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	maxOrdinarySourceLines = 800
	maxTestSourceLines     = 5000
)

func sourceFileFindings(
	files []string,
	readFile func(string) ([]byte, error),
) []string {
	var findings []string
	for _, file := range files {
		if !governedSourceExtension(filepath.Ext(file)) {
			continue
		}
		base := filepath.Base(file)
		intent := strings.TrimSuffix(
			strings.TrimSuffix(base, filepath.Ext(base)), "_test",
		)
		if vagueSourceIntent(intent) {
			findings = append(findings,
				fmt.Sprintf("%s: vague accumulation filename is prohibited", file),
			)
		}
		if base == "coverage_test.go" {
			findings = append(findings,
				fmt.Sprintf("%s: use an intent-named residual coverage file", file),
			)
		}
		source, err := readFile(file)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		if generatedSource(source) {
			continue
		}
		lines := bytes.Count(source, []byte{'\n'})
		if len(source) > 0 && source[len(source)-1] != '\n' {
			lines++
		}
		if strings.Contains(base, "_test.") && lines > maxTestSourceLines {
			findings = append(findings,
				fmt.Sprintf("%s: test file exceeds the 5,000-line maximum", file),
			)
		} else if !strings.Contains(base, "_test.") &&
			lines > maxOrdinarySourceLines {
			findings = append(findings,
				fmt.Sprintf("%s: source file exceeds the 800-line exceptional maximum", file),
			)
		}
	}
	return findings
}

func governedSourceExtension(extension string) bool {
	switch strings.ToLower(extension) {
	case ".go", ".rs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx":
		return true
	default:
		return false
	}
}

func vagueSourceIntent(intent string) bool {
	switch intent {
	case "additional", "more", "extended", "misc", "extra", "helper",
		"helpers", "util", "utils", "common":
		return true
	default:
		return false
	}
}

func generatedSource(source []byte) bool {
	lines := bytes.SplitN(source, []byte{'\n'}, 31)
	if len(lines) > 30 {
		lines = lines[:30]
	}
	for _, line := range lines {
		text := string(line)
		if strings.HasPrefix(text, "// Code generated ") &&
			strings.HasSuffix(text, " DO NOT EDIT.") {
			return true
		}
	}
	return false
}
