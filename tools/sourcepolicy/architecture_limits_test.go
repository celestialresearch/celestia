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
	"strings"
	"testing"
	"time"
)

func TestArchitectureReadBudgetRejectsAggregateInput(t *testing.T) {
	t.Parallel()

	chunk := []byte(strings.Repeat("x", maxSourceBytes))
	budget := newArchitectureReadBudget(
		func(string) ([]byte, error) { return chunk, nil }, time.Now,
	)
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

func TestArchitectureReadBudgetRejectsDeadline(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	budget := newArchitectureReadBudget(
		func(string) ([]byte, error) {
			now = now.Add(maxArchitectureDuration)
			return []byte("source"), nil
		},
		func() time.Time { return now },
	)
	if _, err := budget.readFile("source.go"); err == nil ||
		!strings.Contains(err.Error(), "deadline") {
		t.Fatalf("deadline error = %v", err)
	}
}
