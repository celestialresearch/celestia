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

	"go.yaml.in/yaml/v3"
)

func golangciConfigFindings(path string, source []byte) []string {
	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		return []string{fmt.Sprintf(
			"%s: parse golangci-lint configuration: %v",
			path,
			err,
		)}
	}
	var findings []string
	for _, owner := range []string{"linters", "formatters"} {
		if _, exists := nestedTable(document, owner)["exclusions"]; exists {
			findings = append(findings, fmt.Sprintf(
				"%s: golangci-lint %s exclusions are prohibited",
				path,
				owner,
			))
		}
	}
	return findings
}
