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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var errWrite = errors.New("write failed")

type failingWriter struct{}

type failingReader struct{}

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

const codeQLTestPrefix = `permissions: read-all
jobs:
  analyze:
    permissions: {security-events: write}
`

func (failingWriter) Write([]byte) (int, error) {
	return 0, errWrite
}

func (failingReader) Read([]byte) (int, error) {
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
		{
			name:  "action step reference mapping",
			path:  "action.yml",
			input: "runs:\n  steps:\n    - uses: {}\n",
			mode:  actionsMode,
			want:  "action reference must be scalar",
		},
		{
			name:  "service image mapping",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    services:\n      database:\n        image: {}\n",
			mode:  actionsMode,
			want:  "container image must be scalar",
		},
	})
}

func TestYAMLValidatorRejectsCycleAndComplexKey(t *testing.T) {
	t.Parallel()
	validator := yamlValidator{
		active:    make(map[*yaml.Node]bool),
		remaining: maxYAMLNodeVisits,
	}
	cyclic := &yaml.Node{Kind: yaml.MappingNode}
	alias := &yaml.Node{Kind: yaml.AliasNode, Alias: cyclic}
	cyclic.Content = []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "cycle"},
		alias,
	}
	if err := validator.validate(cyclic, 0); err == nil ||
		!strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle error = %v", err)
	}
	if err := validator.validateMapping(&yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.SequenceNode},
			{Kind: yaml.ScalarNode},
		},
	}, 0); err == nil {
		t.Fatal("non-scalar mapping key accepted")
	}
}

func TestReadFieldBoundaries(t *testing.T) {
	t.Parallel()
	value, eof, err := readField(
		bufio.NewReader(strings.NewReader(strings.Repeat("a", 5000)+"\x00")),
		6000,
		false,
	)
	if err != nil || eof || len(value) != 5000 {
		t.Fatalf("buffered field length=%d eof=%t error=%v", len(value), eof, err)
	}
	if _, _, err := readField(
		bufio.NewReader(strings.NewReader("\x00")), 1, false,
	); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty field error = %v", err)
	}
	if _, _, err := readField(
		bufio.NewReaderSize(failingReader{}, 1), 1, false,
	); !errors.Is(err, errWrite) {
		t.Fatalf("reader error = %v", err)
	}
	if _, _, err := readField(
		bufio.NewReader(io.LimitReader(strings.NewReader("abc"), 3)),
		3,
		false,
	); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated field error = %v", err)
	}
}

func TestPermissionWorkflowBoundaries(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"no jobs": "permissions: read-all\n",
		"scalar job": `permissions: read-all
jobs:
  ignored: scalar
`,
		"job without write": `permissions: read-all
jobs:
  inspect:
    permissions: read-all
`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := inspectForFuzz([]byte(input), permissionsMode); err != nil {
				t.Fatalf("inspect permissions: %v", err)
			}
		})
	}

}

func TestPermissionWorkflowRejectsInvalidCodeQL(t *testing.T) {
	t.Parallel()
	testInvalidDocuments(t, []invalidDocument{
		{
			name:  "invalid workflow permissions",
			path:  "main.yml",
			input: "permissions: []\n",
			mode:  permissionsMode,
			want:  "workflow permissions",
		},
		{
			name:  "invalid jobs",
			path:  "main.yml",
			input: "permissions: read-all\njobs: []\n",
			mode:  permissionsMode,
			want:  "jobs must be a mapping",
		},
		{
			name:  "CodeQL steps missing",
			path:  ".github/workflows/codeql.yml",
			input: codeQLTestPrefix,
			mode:  permissionsMode,
			want:  "steps must be a sequence",
		},
		{
			name: "CodeQL actions missing",
			path: ".github/workflows/codeql.yml",
			input: codeQLTestPrefix + `    steps:
      - uses: actions/setup-go@0123456789012345678901234567890123456789
`,
			mode: permissionsMode,
			want: "exactly one CodeQL",
		},
		{
			name:  "CodeQL steps empty",
			path:  ".github/workflows/codeql.yml",
			input: codeQLTestPrefix + "    steps: []\n",
			mode:  permissionsMode,
			want:  "exactly one CodeQL",
		},
		{
			name: "CodeQL scalar step",
			path: ".github/workflows/codeql.yml",
			input: codeQLTestPrefix + `    steps:
      - invalid
`,
			mode: permissionsMode,
			want: "step must be a mapping",
		},
		{
			name: "CodeQL step without action",
			path: ".github/workflows/codeql.yml",
			input: codeQLTestPrefix + `    steps:
      - name: invalid
`,
			mode: permissionsMode,
			want: "approved action",
		},
		{
			name: "conditional CodeQL initialisation",
			path: ".github/workflows/codeql.yml",
			input: codeQLTestPrefix + `    steps:
      - uses: github/codeql-action/init@0123456789012345678901234567890123456789
        if: always()
`,
			mode: permissionsMode,
			want: "initialisation must be unconditional",
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

func FuzzInspectWorkflow(f *testing.F) {
	f.Add([]byte("name: test\njobs: {}\n"))
	f.Add([]byte("name: test\npermissions: read-all\njobs: {}\n"))
	f.Add([]byte("name: &name test\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@0123456789012345678901234567890123456789\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxActionDocumentBytes {
			return
		}
		for _, mode := range []string{actionsMode, permissionsMode} {
			firstOutput, firstErr := inspectForFuzz(data, mode)
			secondOutput, secondErr := inspectForFuzz(data, mode)
			if firstOutput != secondOutput ||
				fmt.Sprint(firstErr) != fmt.Sprint(secondErr) {
				t.Fatalf("inspection is nondeterministic for mode %s", mode)
			}
			if len(firstOutput) > maxActionCorpusBytes {
				t.Fatalf("inspection output exceeds corpus bound for mode %s", mode)
			}
			firstOutput, firstErr = inspectStreamForFuzz(data, mode)
			secondOutput, secondErr = inspectStreamForFuzz(data, mode)
			if firstOutput != secondOutput ||
				fmt.Sprint(firstErr) != fmt.Sprint(secondErr) {
				t.Fatalf("stream inspection is nondeterministic for mode %s", mode)
			}
			if len(firstOutput) > maxActionCorpusBytes {
				t.Fatalf("stream output exceeds corpus bound for mode %s", mode)
			}
		}
	})
}

func inspectForFuzz(data []byte, mode string) (string, error) {
	var output bytes.Buffer
	err := inspect(document{
		path: ".github/workflows/fuzz.yml",
		data: data,
	}, mode, &output)
	return output.String(), err
}

func inspectStreamForFuzz(data []byte, mode string) (string, error) {
	var output bytes.Buffer
	err := inspectDocuments(bytes.NewReader(data), &output, mode, streamLimits{
		documents:  maxActionDocuments,
		pathBytes:  maxActionPathBytes,
		dataBytes:  maxActionDocumentBytes,
		totalBytes: maxActionCorpusBytes,
	})
	return output.String(), err
}
