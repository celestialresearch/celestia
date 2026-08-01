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
	"path"
	"strings"
)

func architectureWindowsBinaryFindings(
	files []string, readFile func(string) ([]byte, error),
) ([]string, error) {
	var findings []string
	for _, file := range files {
		data, err := readFile(file)
		if err != nil {
			return nil, err
		}
		portableExecutable := len(data) >= 2 && data[0] == 'M' && data[1] == 'Z'
		if !portableExecutable && !architectureWindowsBinaryExtension(path.Ext(file)) {
			continue
		}
		detail := "Windows executable artefact is not declared"
		if portableExecutable {
			detail = "PE executable artefact is not declared"
		}
		findings = append(findings, file+": "+detail)
	}
	return findings, nil
}

func architectureWindowsBinaryExtension(extension string) bool {
	switch strings.ToLower(extension) {
	case ".com", ".cpl", ".dll", ".exe", ".ocx", ".pif", ".scr", ".sys":
		return true
	default:
		return false
	}
}
