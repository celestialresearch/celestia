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

func TestArchitectureEvaluationJoinsBlockedReader(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	readerFinished := make(chan struct{})
	started := make(chan struct{})
	returned := make(chan int, 1)
	released := false
	releaseReader := func() {
		if !released {
			close(release)
			released = true
		}
	}
	var stderr bytes.Buffer
	t.Cleanup(func() {
		releaseReader()
		select {
		case <-readerFinished:
		case <-time.After(time.Second):
			t.Error("blocked architecture reader did not finish")
		}
	})
	go func() {
		returned <- runArchitecturePolicy(
			&stderr,
			func() ([]string, error) { return []string{"go.mod"}, nil },
			noExecutableSources,
			func(string) ([]byte, error) {
				close(started)
				<-release
				close(readerFinished)
				return nil, errors.New("reader released")
			},
		)
	}()
	<-started
	select {
	case status := <-returned:
		t.Fatalf("blocked evaluation returned status %d", status)
	default:
	}
	releaseReader()
	select {
	case <-readerFinished:
	case <-time.After(time.Second):
		t.Fatal("blocked architecture reader did not finish")
	}
	select {
	case status := <-returned:
		if status != 1 || !strings.Contains(stderr.String(), "reader released") {
			t.Fatalf("status = %d, stderr = %q", status, stderr.String())
		}
	case <-time.After(time.Second):
		t.Fatal("blocked architecture evaluation did not join")
	}
}
