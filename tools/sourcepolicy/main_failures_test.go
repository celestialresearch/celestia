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

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunFailureReporting(t *testing.T) {
	inventoryFailure := func() ([]string, error) {
		return nil, errors.New("inventory failed")
	}
	validInventory := func() ([]string, error) {
		return []string{"broken_test.go"}, nil
	}
	readBrokenGo := func(string) ([]byte, error) {
		return []byte("package broken\nfunc TestBroken("), nil
	}
	readEmpty := func(string) ([]byte, error) { return nil, nil }
	tests := []struct {
		name      string
		args      []string
		inventory func() ([]string, error)
		read      func(string) ([]byte, error)
	}{
		{"usage write", nil, validInventory, readEmpty},
		{"inventory write", []string{modeTestSkips}, inventoryFailure, readEmpty},
		{"policy write", []string{modeTestSkips}, validInventory, readBrokenGo},
		{"finding write", []string{modeSuppressions}, validInventory, func(string) ([]byte, error) {
			return []byte("//no" + "lint"), nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if code := run(test.args, failingWriter{}, test.inventory, test.read); code != 1 {
				t.Fatalf("run code = %d, want 1", code)
			}
		})
	}

	var stderr bytes.Buffer
	if code := run(
		[]string{modeTestSkips},
		&stderr,
		validInventory,
		readBrokenGo,
	); code != 1 || !strings.Contains(stderr.String(), "parse Go test") {
		t.Fatalf("policy failure = %d, %q", code, stderr.String())
	}
}
