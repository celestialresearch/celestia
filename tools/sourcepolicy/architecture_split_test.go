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
	"slices"
	"strings"
	"testing"
)

func TestArchitectureRejectsUnsplitSources(t *testing.T) {
	t.Parallel()

	for _, file := range []string{
		"internal/operation/urlreference/transform/urlreference.go",
		"internal/operation/urlreference/protocol/protocol_test.go",
		"worker/url-reference/src/tests.rs",
	} {
		assertSplitFinding(t, []string{file}, "obsolete split source")
	}
}

func TestArchitectureRequiresSplitDestinations(t *testing.T) {
	t.Parallel()

	files := expectedSplitFiles()
	files = slices.DeleteFunc(files, func(file string) bool {
		return file == "internal/operation/urlreference/transform/host.go"
	})
	findings := missingSplitSourceFindings(files)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, "required split source is missing")
	}) {
		t.Fatalf("findings = %v, want missing destination", findings)
	}
}

func TestArchitectureRejectsUndeclaredSplitSource(t *testing.T) {
	t.Parallel()

	files := append(expectedSplitFiles(),
		"internal/operation/urlreference/protocol/duplicate.go",
	)
	assertSplitFinding(t, files, "undeclared split source")
}

func assertSplitFinding(t *testing.T, files []string, fragment string) {
	t.Helper()
	findings := architecturePathFindings(
		files, nil, validArchitectureFixturePolicy(),
	)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, fragment)
	}) {
		t.Fatalf("findings = %v, want %q", findings, fragment)
	}
}

func expectedSplitFiles() []string {
	return []string{
		"internal/operation/urlreference/transform/benchmark_test.go",
		"internal/operation/urlreference/transform/conformance_test.go",
		"internal/operation/urlreference/transform/doc.go",
		"internal/operation/urlreference/transform/hex_test.go",
		"internal/operation/urlreference/transform/host.go",
		"internal/operation/urlreference/transform/parse.go",
		"internal/operation/urlreference/transform/text.go",
		"internal/operation/urlreference/transform/transform.go",
		"internal/operation/urlreference/transform/urlreference_test.go",
		"internal/operation/urlreference/protocol/benchmark_test.go",
		"internal/operation/urlreference/protocol/doc.go",
		"internal/operation/urlreference/protocol/frame.go",
		"internal/operation/urlreference/protocol/frame_test.go",
		"internal/operation/urlreference/protocol/fuzz_test.go",
		"internal/operation/urlreference/protocol/protocol.go",
		"internal/operation/urlreference/protocol/request.go",
		"internal/operation/urlreference/protocol/request_test.go",
		"internal/operation/urlreference/protocol/response.go",
		"internal/operation/urlreference/protocol/response_test.go",
		"worker/url-reference/src/main.rs",
		"worker/url-reference/src/protocol.rs",
		"worker/url-reference/src/transform.rs",
		"worker/url-reference/src/tests/mod.rs",
		"worker/url-reference/src/tests/protocol.rs",
		"worker/url-reference/src/tests/transform.rs",
	}
}
