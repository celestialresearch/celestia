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

func TestPermissionsResolveAliases(t *testing.T) {
	t.Parallel()

	stream := "main.yml\x00" + `access: &access write
permissions:
  contents: read
jobs:
  classify:
    permissions:
      security-events: *access
    steps:
      - run: echo classify
` + "\x00"
	err := inspectDocuments(
		strings.NewReader(stream),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err == nil || !strings.Contains(err.Error(), "only the reviewed CodeQL analysis job") {
		t.Fatalf("inspectDocuments() error = %v, want permission rejection", err)
	}
}

func TestPermissionsRetainSecurityWriteAcrossEntries(t *testing.T) {
	t.Parallel()

	input := `permissions: read-all
jobs:
  classify:
    permissions:
      security-events: write
      contents: read
    steps:
      - run: echo classify
`
	err := inspectDocuments(
		strings.NewReader("main.yml\x00"+input+"\x00"),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err == nil || !strings.Contains(err.Error(), "only the reviewed CodeQL analysis job") {
		t.Fatalf("inspectDocuments() error = %v, want permission rejection", err)
	}
}

func TestPermissionsAcceptCodeQLAnalysis(t *testing.T) {
	t.Parallel()

	input := `permissions:
  contents: read
jobs:
  analyze:
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false
      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`
	err := inspectDocuments(
		strings.NewReader(".github/workflows/codeql.yml\x00"+input+"\x00"),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 1024, totalBytes: 1088},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}
}

func TestPermissionsRejectUnreviewedCodeQLAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		path  string
		steps string
		want  string
	}{
		{
			name: "wrong workflow",
			path: "main.yml",
			steps: `      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`,
			want: "only the reviewed CodeQL analysis job",
		},
		{
			name: "run step",
			path: ".github/workflows/codeql.yml",
			steps: `      - run: echo "${{ github.token }}"
      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`,
			want: "run steps are prohibited",
		},
		{
			name: "disabled analysis",
			path: ".github/workflows/codeql.yml",
			steps: `      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
        if: false
`,
			want: "analysis must be unconditional",
		},
		{
			name: "unapproved action",
			path: ".github/workflows/codeql.yml",
			steps: `      - uses: example/privileged@0000000000000000000000000000000000000000
      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`,
			want: "is not approved",
		},
		{
			name: "checkout credentials",
			path: ".github/workflows/codeql.yml",
			steps: `      - uses: actions/checkout@0000000000000000000000000000000000000000
      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`,
			want: "checkout must disable credential persistence",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := `permissions:
  contents: read
jobs:
  analyze:
    permissions:
      contents: read
      security-events: write
    steps:
` + test.steps
			err := inspectDocuments(
				strings.NewReader(test.path+"\x00"+input+"\x00"),
				&bytes.Buffer{},
				permissionsMode,
				streamLimits{documents: 1, pathBytes: 64, dataBytes: 1024, totalBytes: 1088},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inspectDocuments() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPermissionsRejectMalformedCheckoutConfiguration(t *testing.T) {
	t.Parallel()

	for name, configuration := range map[string]string{
		"empty":      "{}",
		"non-scalar": "{persist-credentials: []}",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			input := `permissions:
  contents: read
jobs:
  analyze:
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with: ` + configuration + `
      - uses: github/codeql-action/init@0000000000000000000000000000000000000000
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`
			err := inspectDocuments(
				strings.NewReader(".github/workflows/codeql.yml\x00"+input+"\x00"),
				&bytes.Buffer{},
				permissionsMode,
				streamLimits{
					documents:  1,
					pathBytes:  64,
					dataBytes:  1024,
					totalBytes: 1088,
				},
			)
			if err == nil ||
				!strings.Contains(err.Error(), "checkout must disable credential persistence") {
				t.Fatalf("inspectDocuments() error = %v, want credential rejection", err)
			}
		})
	}
}

func TestPermissionsRejectWriteAll(t *testing.T) {
	t.Parallel()

	input := `permissions:
  contents: read
jobs:
  analyze:
    permissions: write-all
    steps:
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000000
`
	err := inspectDocuments(
		strings.NewReader("main.yml\x00"+input+"\x00"),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err == nil || !strings.Contains(err.Error(), "write-all is prohibited") {
		t.Fatalf("inspectDocuments() error = %v, want write-all rejection", err)
	}
}

func TestPermissionsRequireWorkflowDefault(t *testing.T) {
	t.Parallel()

	input := `jobs:
  inspect:
    permissions:
      contents: read
    steps:
      - run: "true"
`
	err := inspectDocuments(
		strings.NewReader("main.yml\x00"+input+"\x00"),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err == nil || !strings.Contains(err.Error(), "explicit permissions are required") {
		t.Fatalf("inspectDocuments() error = %v, want explicit permission rejection", err)
	}
}

func TestPermissionsIgnoreActionMetadata(t *testing.T) {
	t.Parallel()

	input := `name: Example
runs:
  using: composite
  steps:
    - run: "true"
      shell: bash
`
	err := inspectDocuments(
		strings.NewReader("action.yml\x00"+input+"\x00"),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err != nil {
		t.Fatalf("inspectDocuments() error = %v", err)
	}
}

func TestPermissionsDoNotExemptWorkflowNamedAction(t *testing.T) {
	t.Parallel()

	input := `jobs:
  inspect:
    steps:
      - run: "true"
`
	err := inspectDocuments(
		strings.NewReader(".github/workflows/action.yml\x00"+input+"\x00"),
		&bytes.Buffer{},
		permissionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 512, totalBytes: 576},
	)
	if err == nil || !strings.Contains(err.Error(), "explicit permissions are required") {
		t.Fatalf("inspectDocuments() error = %v, want workflow permission rejection", err)
	}
}

func TestValidatePermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		allowWrite bool
		wantWrite  bool
		wantError  string
	}{
		{name: "none"},
		{name: "read all", input: "read-all"},
		{name: "write all", input: "write-all", wantError: "write-all is prohibited"},
		{name: "invalid scalar", input: "invalid", wantError: "read-all or a mapping"},
		{name: "contents only", input: "{contents: read}"},
		{name: "security read", input: "{security-events: read}"},
		{name: "security none", input: "{security-events: none}"},
		{
			name:       "security write",
			input:      "{security-events: write}",
			allowWrite: true,
			wantWrite:  true,
		},
		{
			name:      "workflow security write",
			input:     "{security-events: write}",
			wantError: "write permission is prohibited",
		},
		{
			name:      "contents write",
			input:     "{contents: write}",
			wantError: "write permission is prohibited",
		},
		{
			name:      "identity token write",
			input:     "{id-token: write}",
			wantError: "write permission is prohibited",
		},
		{
			name:      "security invalid",
			input:     "{security-events: invalid}",
			wantError: "permission is unsupported",
		},
		{
			name:      "security sequence",
			input:     "{security-events: []}",
			wantError: "must be scalar",
		},
		{name: "sequence", input: "[]", wantError: "must be a mapping"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var node *yaml.Node
			if test.input != "" {
				var document yaml.Node
				if err := yaml.Unmarshal([]byte(test.input), &document); err != nil {
					t.Fatalf("yaml.Unmarshal() error = %v", err)
				}
				node = document.Content[0]
			}
			write, err := validatePermissions(node, test.allowWrite)
			if write != test.wantWrite {
				t.Errorf(
					"validatePermissions() write = %t, want %t",
					write,
					test.wantWrite,
				)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validatePermissions() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validatePermissions() error = %v, want %q", err, test.wantError)
			}
		})
	}
}
