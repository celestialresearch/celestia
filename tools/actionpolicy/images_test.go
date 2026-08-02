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
	"strings"
	"testing"
)

func TestInspectDocumentsInventoriesImages(t *testing.T) {
	t.Parallel()

	input := `jobs:
  scan:
    container: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    services:
      database:
        image: postgres:latest
    steps:
      - uses: docker://busybox:latest
`
	stream := "main.yml\x00" + input + "\x00"
	var output bytes.Buffer
	err := inspectDocuments(
		strings.NewReader(stream),
		&output,
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 1024, totalBytes: 1088},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}

	for _, reference := range []string{
		"docker://alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"docker://postgres:latest",
		"docker://busybox:latest",
	} {
		if !strings.Contains(output.String(), reference) {
			t.Errorf("output omitted %q:\n%s", reference, output.String())
		}
	}
}

func TestInspectDocumentsInventoriesDockerAction(t *testing.T) {
	t.Parallel()

	stream := "action.yml\x00runs:\n  using: docker\n  image: docker://alpine:latest\n\x00"
	var output bytes.Buffer
	err := inspectDocuments(
		strings.NewReader(stream),
		&output,
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 256, totalBytes: 320},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}
	if !strings.Contains(output.String(), "docker://alpine:latest") {
		t.Fatalf("output omitted Docker action image:\n%s", output.String())
	}
}

func TestInspectDocumentsIgnoresLocalDockerfile(t *testing.T) {
	t.Parallel()

	stream := "action.yml\x00runs:\n  using: docker\n  image: Dockerfile\n\x00"
	var output bytes.Buffer
	err := inspectDocuments(
		strings.NewReader(stream),
		&output,
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 256, totalBytes: 320},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("local Dockerfile was inventoried: %q", output.String())
	}
}

func TestInspectDocumentsPreservesDockerImagePrefix(t *testing.T) {
	t.Parallel()

	input := `jobs:
  inspect:
    container: docker://alpine:latest
`
	var output bytes.Buffer
	err := inspectDocuments(
		strings.NewReader("main.yml\x00"+input+"\x00"),
		&output,
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 256, totalBytes: 320},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}
	if output.String() != "main.yml:3:docker://alpine:latest\n" {
		t.Fatalf("inspectDocuments() output = %q", output.String())
	}
}
