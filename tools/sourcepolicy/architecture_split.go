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

import "strings"

type splitDirectory struct {
	path  string
	files []string
}

func splitDirectories() []splitDirectory {
	return []splitDirectory{
		{
			path: "internal/operation/urlreference/transform",
			files: []string{
				"benchmark_test.go", "conformance_test.go", "doc.go", "hex_test.go",
				"host.go", "parse.go", "text.go", "transform.go", "urlreference_test.go",
			},
		},
		{
			path: "internal/operation/urlreference/protocol",
			files: []string{
				"benchmark_test.go", "doc.go", "frame.go", "frame_test.go", "fuzz_test.go",
				"protocol.go", "request.go", "request_test.go", "response.go", "response_test.go",
			},
		},
		{
			path: "worker/url-reference/src",
			files: []string{
				"main.rs", "protocol.rs", "tests/mod.rs", "tests/protocol.rs",
				"tests/transform.rs", "transform.rs",
			},
		},
	}
}

func splitSourcePathFindings(files []string) []string {
	allowed := splitSourceSet()
	obsolete := stringSet([]string{
		"internal/operation/urlreference/transform/urlreference.go",
		"internal/operation/urlreference/protocol/protocol_test.go",
		"worker/url-reference/src/tests.rs",
	})
	var findings []string
	for _, file := range files {
		if _, denied := obsolete[file]; denied {
			findings = append(findings, file+": obsolete split source")
			continue
		}
		if governedSplitPath(file) {
			if _, declared := allowed[file]; !declared {
				findings = append(findings, file+": undeclared split source")
			}
		}
	}
	return boundedArchitectureFindings(findings)
}

func missingSplitSourceFindings(files []string) []string {
	tracked := stringSet(files)
	var findings []string
	for file := range splitSourceSet() {
		if _, exists := tracked[file]; !exists {
			findings = append(findings, file+": required split source is missing")
		}
	}
	return boundedArchitectureFindings(findings)
}

func splitSourceSet() map[string]struct{} {
	files := make(map[string]struct{})
	for _, directory := range splitDirectories() {
		for _, file := range directory.files {
			files[directory.path+"/"+file] = struct{}{}
		}
	}
	return files
}

func governedSplitPath(file string) bool {
	for _, directory := range splitDirectories() {
		if strings.HasPrefix(file, directory.path+"/") {
			return true
		}
	}
	return false
}
