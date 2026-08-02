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
	"errors"
	"strings"
	"testing"
)

type stagedWriter struct {
	failAt int
	writes int
}

func (writer *stagedWriter) Write(value []byte) (int, error) {
	writer.writes++
	if writer.writes == writer.failAt {
		return 0, errWrite
	}
	return len(value), nil
}

func TestInspectDocumentsAcceptsOrdinaryEmptyInventory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		path  string
		input string
	}{
		{
			name: "composite action without image",
			path: "action.yml",
			input: `runs:
  using: composite
  steps:
    - run: "true"
      shell: bash
`,
		},
		{
			name: "JavaScript action image",
			path: "action.yml",
			input: `runs:
  using: node20
  main: index.js
`,
		},
		{
			name: "empty steps",
			path: "main.yml",
			input: `jobs:
  inspect:
    steps: []
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			err := inspectDocuments(
				strings.NewReader(test.path+"\x00"+test.input+"\x00"),
				&output,
				actionsMode,
				streamLimits{
					documents:  1,
					pathBytes:  64,
					dataBytes:  512,
					totalBytes: 576,
				},
			)
			if err != nil {
				t.Fatalf("inspectDocuments() error = %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("inspectDocuments() output = %q, want empty", output.String())
			}
		})
	}
}

func TestInspectDocumentsPropagatesOutputFailure(t *testing.T) {
	t.Parallel()

	stream := "main.yml\x00jobs:\n  scan:\n    uses: example/action@main\n\x00"
	err := inspectDocuments(
		strings.NewReader(stream),
		failingWriter{},
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 256, totalBytes: 320},
	)
	if !errors.Is(err, errWrite) {
		t.Fatalf("inspectDocuments() error = %v, want %v", err, errWrite)
	}
}

func TestInspectDocumentsPropagatesEveryOutputFailure(t *testing.T) {
	t.Parallel()

	stream := "main.yml\x00jobs:\n  scan:\n    uses: example/action@main # release\n\x00"
	for _, failAt := range []int{2, 3} {
		writer := &stagedWriter{failAt: failAt}
		err := inspectDocuments(
			strings.NewReader(stream),
			writer,
			actionsMode,
			streamLimits{documents: 1, pathBytes: 64, dataBytes: 256, totalBytes: 320},
		)
		if !errors.Is(err, errWrite) {
			t.Fatalf("write %d error = %v, want %v", failAt, err, errWrite)
		}
	}
}
