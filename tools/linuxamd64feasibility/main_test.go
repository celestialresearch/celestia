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
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRunRequiresOneRoot(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := run(nil, &stdout, &stderr); status != 2 || stdout.Len() != 0 ||
		stderr.String() != "usage: linuxamd64feasibility <evidence-root>\n" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestBootstrapRefusesUnsupportedPlatform(t *testing.T) {
	if status := runBootstrap(nil, nil); status != 1 {
		t.Fatalf("status = %d", status)
	}
}

func TestBootstrapStatus(t *testing.T) {
	if bootstrapStatus(nil) != 0 || bootstrapStatus(errors.New("bootstrap")) != 1 {
		t.Fatal("incorrect bootstrap status")
	}
}

func TestRunMainDispatchesOrdinaryMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := runMain(nil, &stdout, &stderr); status != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestRunMainDispatchesBootstrapMode(t *testing.T) {
	if status := runMain([]string{"--bootstrap"}, &bytes.Buffer{}, &bytes.Buffer{}); status != 1 {
		t.Fatalf("status=%d", status)
	}
}

func TestRunEmitsPreflightResult(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := run([]string{t.TempDir()}, &stdout, &stderr); status != 0 ||
		stderr.Len() != 0 || !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	var result struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil ||
		(result.Status != "unavailable" && result.Status != "indeterminate") ||
		result.Reason == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRunReportsWriteFailure(t *testing.T) {
	var stderr bytes.Buffer
	if status := run([]string{t.TempDir()}, failingWriter{}, &stderr); status != 1 || stderr.Len() != 0 {
		t.Fatalf("status=%d stderr=%q", status, stderr.String())
	}
}

func TestWriteResult(t *testing.T) {
	var output bytes.Buffer
	if err := writeResult(&output, []byte("result")); err != nil || output.String() != "result" {
		t.Fatalf("output=%q error=%v", output.String(), err)
	}
}

func TestRunReportsUsageWriteFailure(t *testing.T) {
	if status := run(nil, failingWriter{}, failingWriter{}); status != 1 {
		t.Fatalf("status=%d", status)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write")
}
