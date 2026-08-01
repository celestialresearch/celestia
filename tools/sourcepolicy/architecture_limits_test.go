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
	"time"
)

func TestArchitectureReadBudgetRejectsAggregateInput(t *testing.T) {
	t.Parallel()

	chunk := []byte(strings.Repeat("x", maxSourceBytes))
	budget := newArchitectureReadBudget(func(string) ([]byte, error) { return chunk, nil })
	for range maxArchitectureInputBytes / len(chunk) {
		if _, err := budget.readFile("source.go"); err != nil {
			t.Fatalf("bounded input rejected early: %v", err)
		}
	}
	if _, err := budget.readFile("excess.go"); err == nil ||
		!strings.Contains(err.Error(), "aggregate size") {
		t.Fatalf("aggregate input error = %v", err)
	}
}

func TestArchitectureEvaluationDeadline(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	finished := make(chan struct{})
	var stderr bytes.Buffer
	status := runArchitecturePolicyWithin(
		&stderr,
		func() ([]string, error) {
			<-release
			close(finished)
			return nil, nil
		},
		noExecutableSources,
		func(string) ([]byte, error) { return nil, nil },
		20*time.Millisecond,
	)
	if status != 1 || !strings.Contains(stderr.String(), "deadline") {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("blocked architecture evaluation did not finish")
	}
}
