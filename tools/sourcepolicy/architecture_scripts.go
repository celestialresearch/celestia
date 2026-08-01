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
	"path"
)

func architectureShebangFindings(
	files, declaredScripts []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	declared := stringSet(declaredScripts)
	var findings []string
	for _, file := range files {
		if path.Ext(file) != "" {
			continue
		}
		source, err := readFile(file)
		if err != nil {
			return nil, fmt.Errorf("read possible script %s: %w", file, err)
		}
		if bytes.HasPrefix(source, []byte("#!")) {
			if _, allowed := declared[file]; !allowed {
				findings = append(findings, file+": script is not declared")
			}
		}
	}
	return findings, nil
}
