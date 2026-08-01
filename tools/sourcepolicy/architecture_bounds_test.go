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
	"strconv"
	"strings"
	"testing"
)

func TestArchitectureFindingsAreBounded(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	files := make([]string, maxArchitectureFindings+1)
	for index := range files {
		files[index] = "unapproved" + strconv.Itoa(index) + "/" +
			strings.Repeat("a", maxInventoryPathBytes-64) + ".go"
	}
	findings := architecturePathFindings(files, nil, policy)
	if len(findings) != maxArchitectureFindings+1 ||
		findings[len(findings)-1] != architectureTruncated {
		t.Fatalf("architecturePathFindings() returned %d unbounded findings", len(findings))
	}
	if len(strings.Join(findings, "\n"))+1 > maxSourceBytes {
		t.Fatal("bounded architecture diagnostics exceed the output contract")
	}
}

func TestArchitectureErrorsAreBounded(t *testing.T) {
	t.Parallel()

	unknown := strings.Repeat("x", maxSourceBytes-6)
	policy := []byte(`{"` + unknown + `":0}`)
	var stderr bytes.Buffer
	status := runArchitecturePolicy(
		&stderr,
		func() ([]string, error) { return []string{"go.mod"}, nil },
		noExecutableSources,
		func(string) ([]byte, error) { return policy, nil },
	)
	if status != 1 || stderr.Len() > maxSourceBytes {
		t.Fatalf("status = %d, diagnostic bytes = %d", status, stderr.Len())
	}
	if stderr.String() != "architecture diagnostic exceeded its output bound\n" {
		t.Fatalf("diagnostic = %q", stderr.String())
	}
}
