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

	"go.yaml.in/yaml/v3"
)

type invalidDocument struct {
	name  string
	path  string
	input string
	mode  string
	want  string
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
		{
			name:  "empty root",
			path:  "main.yml",
			input: " \n",
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

func TestYAMLHelpersRejectConstructedInvalidNodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node *yaml.Node
	}{
		{
			name: "incomplete mapping",
			node: &yaml.Node{
				Kind:    yaml.MappingNode,
				Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "key"}},
			},
		},
		{
			name: "nil mapping key",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					nil,
					{Kind: yaml.ScalarNode, Value: "value"},
				},
			},
		},
		{
			name: "alias mapping key",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.AliasNode},
					{Kind: yaml.ScalarNode, Value: "value"},
				},
			},
		},
		{
			name: "non-scalar mapping key",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.SequenceNode},
					{Kind: yaml.ScalarNode, Value: "value"},
				},
			},
		},
		{
			name: "unsupported node kind",
			node: &yaml.Node{Kind: 255},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			validator := yamlValidator{
				active:    make(map[*yaml.Node]bool),
				remaining: maxYAMLNodeVisits,
			}
			if err := validator.validate(test.node, 0); err == nil {
				t.Fatal("constructed invalid node accepted")
			}
		})
	}
}
