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
	"fmt"
	"strings"
	"testing"
)

var errWrite = errors.New("write failed")

type failingWriter struct{}

type stagedWriter struct {
	failAt int
	writes int
}

type invalidDocument struct {
	name  string
	path  string
	input string
	mode  string
	want  string
}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errWrite
}

func (writer *stagedWriter) Write(value []byte) (int, error) {
	writer.writes++
	if writer.writes == writer.failAt {
		return 0, errWrite
	}
	return len(value), nil
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		input      string
		wantStatus int
		wantError  string
	}{
		{name: "actions", args: []string{actionsMode}},
		{name: "permissions", args: []string{permissionsMode}},
		{name: "missing", wantStatus: 2, wantError: "Usage:"},
		{
			name:       "unknown",
			args:       []string{"unknown"},
			wantStatus: 2,
			wantError:  "Usage:",
		},
		{
			name:       "invalid input",
			args:       []string{actionsMode},
			input:      "main.yml\x00invalid: [\x00",
			wantStatus: 1,
			wantError:  "parse workflow",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			var errorOutput bytes.Buffer
			status := run(
				test.args,
				strings.NewReader(test.input),
				&output,
				&errorOutput,
			)
			if status != test.wantStatus {
				t.Fatalf("run() status = %d, want %d", status, test.wantStatus)
			}
			if !strings.Contains(errorOutput.String(), test.wantError) {
				t.Fatalf(
					"run() error = %q, want %q",
					errorOutput.String(),
					test.wantError,
				)
			}
		})
	}
}

func TestRunHandlesDiagnosticFailure(t *testing.T) {
	t.Parallel()

	if status := run(nil, strings.NewReader(""), &bytes.Buffer{}, failingWriter{}); status != 1 {
		t.Fatalf("run() usage status = %d, want 1", status)
	}
	if status := run(
		[]string{actionsMode},
		strings.NewReader("main.yml\x00invalid: [\x00"),
		&bytes.Buffer{},
		failingWriter{},
	); status != 1 {
		t.Fatalf("run() error status = %d, want 1", status)
	}
}

func TestInspectDocumentsBounds(t *testing.T) {
	t.Parallel()

	limits := streamLimits{documents: 1, pathBytes: 5, dataBytes: 8, totalBytes: 13}
	valid := "a.yml\x00jobs: {}\x00"
	tests := []struct {
		name   string
		input  string
		limits streamLimits
		want   string
	}{
		{name: "valid", input: valid, limits: limits},
		{name: "path", input: "ab.yml\x00jobs: {}\x00", limits: limits, want: "field exceeds limit"},
		{name: "document", input: "a.yml\x00jobs: {}\n\x00", limits: limits, want: "field exceeds limit"},
		{name: "count", input: valid + valid, limits: limits, want: "document count exceeds limit"},
		{
			name:   "corpus",
			input:  valid,
			limits: streamLimits{documents: 1, pathBytes: 5, dataBytes: 8, totalBytes: 12},
			want:   "document corpus exceeds limit",
		},
		{name: "truncated path", input: "a.yml", limits: limits, want: "field is truncated"},
		{name: "missing document", input: "a.yml\x00", limits: limits, want: "action document is missing"},
		{name: "truncated document", input: "a.yml\x00jobs:{}", limits: limits, want: "field is truncated"},
		{
			name:   "invalid limits",
			input:  valid,
			limits: streamLimits{},
			want:   "limits must be positive",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := inspectDocuments(
				strings.NewReader(test.input),
				&bytes.Buffer{},
				actionsMode,
				test.limits,
			)
			if test.want == "" {
				if err != nil {
					t.Fatalf("inspectDocuments() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inspectDocuments() error = %v, want %q", err, test.want)
			}
		})
	}
}

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

func TestInspectDocumentsRejectsUnsafeStructure(t *testing.T) {
	t.Parallel()

	testInvalidDocuments(t, []invalidDocument{
		{
			name:  "path newline",
			path:  "main\ninjected.yml",
			input: "jobs: {}",
			mode:  actionsMode,
			want:  "reserved character",
		},
		{
			name:  "path colon",
			path:  "main:injected.yml",
			input: "jobs: {}",
			mode:  actionsMode,
			want:  "reserved character",
		},
		{
			name:  "path UTF-8",
			path:  "main\xff.yml",
			input: "jobs: {}",
			mode:  actionsMode,
			want:  "not valid UTF-8",
		},
		{
			name:  "duplicate key",
			path:  "main.yml",
			input: "permissions: {}\npermissions:\n  security-events: write\n",
			mode:  permissionsMode,
			want:  "duplicate YAML key",
		},
		{
			name: "merge key",
			path: "main.yml",
			input: `shared: &shared
  security-events: write
permissions:
  <<: *shared
`,
			mode: permissionsMode,
			want: "merge keys are unsupported",
		},
		{
			name: "reference newline",
			path: "main.yml",
			input: `jobs:
  scan:
    steps:
      - uses: |
          example/action@main
          injected/action@main
`,
			mode: actionsMode,
			want: "control character",
		},
		{
			name:  "root sequence",
			path:  "main.yml",
			input: "[]",
			mode:  actionsMode,
			want:  "root must be a mapping",
		},
	})
}

func TestInspectDocumentsRejectsAliasKeys(t *testing.T) {
	t.Parallel()

	testInvalidDocuments(t, []invalidDocument{
		{
			name: "action key",
			path: "main.yml",
			input: `name: &uses_key uses
jobs:
  check:
    steps:
      - *uses_key: example/action@main
`,
			mode: actionsMode,
			want: "alias keys are unsupported",
		},
		{
			name: "permission key",
			path: "main.yml",
			input: `name: &permissions_key permissions
*permissions_key:
  security-events: write
`,
			mode: permissionsMode,
			want: "alias keys are unsupported",
		},
		{
			name: "container-image key",
			path: "main.yml",
			input: `name: &image_key image
jobs:
  check:
    container:
      *image_key: alpine:latest
`,
			mode: actionsMode,
			want: "alias keys are unsupported",
		},
	})
}

func TestInspectDocumentsBoundsAliasExpansion(t *testing.T) {
	t.Parallel()

	var input strings.Builder
	input.WriteString("level0: &level0 [value, value, value, value, value, value, value, value, value, value]\n")
	for level := 1; level <= 7; level++ {
		fmt.Fprintf(&input, "level%d: &level%d [", level, level)
		for item := range 10 {
			if item > 0 {
				input.WriteString(", ")
			}
			fmt.Fprintf(&input, "*level%d", level-1)
		}
		input.WriteString("]\n")
	}

	stream := "main.yml\x00" + input.String() + "\x00"
	err := inspectDocuments(
		strings.NewReader(stream),
		&bytes.Buffer{},
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 4096, totalBytes: 4160},
	)
	if err == nil || !strings.Contains(err.Error(), "traversal budget") {
		t.Fatalf("inspectDocuments() error = %v, want traversal budget rejection", err)
	}
}

func TestInspectDocumentsBoundsNesting(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("[", maxYAMLDepth+1) +
		"value" +
		strings.Repeat("]", maxYAMLDepth+1)
	stream := "main.yml\x00value: " + input + "\x00"
	err := inspectDocuments(
		strings.NewReader(stream),
		&bytes.Buffer{},
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 2048, totalBytes: 2112},
	)
	if err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("inspectDocuments() error = %v, want depth rejection", err)
	}
}

func TestInspectDocumentsRejectsInvalidJobs(t *testing.T) {
	t.Parallel()

	testInvalidDocuments(t, []invalidDocument{
		{
			name:  "jobs sequence",
			path:  "main.yml",
			input: "jobs: []",
			mode:  actionsMode,
			want:  "jobs must be a mapping",
		},
		{
			name:  "job scalar",
			path:  "main.yml",
			input: "jobs:\n  scan: invalid\n",
			mode:  actionsMode,
			want:  "job must be a mapping",
		},
		{
			name:  "services sequence",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    services: []\n",
			mode:  actionsMode,
			want:  "services must be a mapping",
		},
		{
			name:  "service scalar",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    services:\n      database: invalid\n",
			mode:  actionsMode,
			want:  "service must be a mapping",
		},
		{
			name:  "missing container image",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    container: {}\n",
			mode:  actionsMode,
			want:  "container image is missing",
		},
		{
			name:  "container image sequence",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    container:\n      image: []\n",
			mode:  actionsMode,
			want:  "container image must be scalar",
		},
	})
}

func TestInspectDocumentsRejectsInvalidSteps(t *testing.T) {
	t.Parallel()

	testInvalidDocuments(t, []invalidDocument{
		{
			name:  "steps mapping",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    steps: {}\n",
			mode:  actionsMode,
			want:  "steps must be a sequence",
		},
		{
			name:  "step scalar",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    steps:\n      - invalid\n",
			mode:  actionsMode,
			want:  "step must be a mapping",
		},
		{
			name:  "uses mapping",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    steps:\n      - uses: {}\n",
			mode:  actionsMode,
			want:  "action reference must be scalar",
		},
		{
			name:  "runs scalar",
			path:  "action.yml",
			input: "runs: invalid\n",
			mode:  actionsMode,
			want:  "runs must be a mapping",
		},
		{
			name:  "action image mapping",
			path:  "action.yml",
			input: "runs:\n  image: {}\n",
			mode:  actionsMode,
			want:  "action image must be scalar",
		},
	})
}

func testInvalidDocuments(t *testing.T, tests []invalidDocument) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stream := test.path + "\x00" + test.input + "\x00"
			err := inspectDocuments(
				strings.NewReader(stream),
				&bytes.Buffer{},
				test.mode,
				streamLimits{
					documents:  1,
					pathBytes:  64,
					dataBytes:  1024,
					totalBytes: 1088,
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inspectDocuments() error = %v, want %q", err, test.want)
			}
		})
	}
}
