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

var errWrite = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errWrite
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
		{name: "verify", args: []string{verifyMode}},
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

func TestVerifyModeOwnsActionsAndPermissions(t *testing.T) {
	t.Parallel()

	const action = "example/action@0000000000000000000000000000000000000001"
	data := []byte("permissions: read-all\njobs:\n  build:\n    steps:\n      - uses: " + action + "\n")
	var output bytes.Buffer
	if err := inspect(document{path: ".github/workflows/main.yml", data: data}, verifyMode, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), action) {
		t.Fatalf("verify output = %q", output.String())
	}

	data = []byte("permissions: write-all\njobs:\n  build:\n    steps:\n      - uses: " + action + "\n")
	output.Reset()
	err := inspect(document{path: ".github/workflows/main.yml", data: data}, verifyMode, &output)
	if err == nil || !strings.Contains(err.Error(), "write-all is prohibited") {
		t.Fatalf("verify error = %v", err)
	}
	if !strings.Contains(output.String(), action) {
		t.Fatalf("verify failure output = %q", output.String())
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
