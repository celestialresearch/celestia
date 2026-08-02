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

func TestInspectDocumentsResolvesReferenceAliases(t *testing.T) {
	t.Parallel()

	stream := "main.yml\x00" + `image: &image alpine:latest
action: &action example/action@main
jobs:
  scan:
    container: *image
    steps:
      - uses: *action
` + "\x00"
	var output bytes.Buffer
	err := inspectDocuments(
		strings.NewReader(stream),
		&output,
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}
	for _, reference := range []string{"docker://alpine:latest", "example/action@main"} {
		if !strings.Contains(output.String(), reference) {
			t.Errorf("output omitted aliased %q:\n%s", reference, output.String())
		}
	}
}
