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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRunManifestPolicy(t *testing.T) {
	t.Parallel()
	data := []byte(`{"schema_version":"test"}`)
	sum := sha256.Sum256(data)
	tests := []struct {
		name     string
		data     []byte
		readErr  error
		expected string
		code     int
	}{
		{"accepted", data, nil, hex.EncodeToString(sum[:]), 0},
		{"changed", data, nil, strings.Repeat("0", 64), 1},
		{"malformed", []byte(`{`), nil, hex.EncodeToString(sum[:]), 1},
		{"read failure", nil, errors.New("read failed"), "", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			code := manifestPolicyStatus(
				&stderr,
				func(string) ([]byte, error) {
					return test.data, test.readErr
				},
				governedManifestPath,
				test.expected,
			)
			if code != test.code {
				t.Fatalf("code = %d, want %d", code, test.code)
			}
		})
	}
}

func TestRunManifestPolicyGovernsEveryManifest(t *testing.T) {
	t.Chdir("../..")

	var stderr bytes.Buffer
	if runManifestPolicy(&stderr, os.ReadFile) != 0 {
		t.Fatalf("reviewed manifests rejected: %s", stderr.String())
	}
	for _, target := range []string{
		governedManifestPath, structureManifestPath, executionManifestPath,
		transformManifestPath,
	} {
		for _, missing := range []bool{false, true} {
			read := func(name string) ([]byte, error) {
				if name == target {
					if missing {
						return nil, errors.New("missing")
					}
					return []byte(`{"schema_version":"changed"}`), nil
				}
				switch name {
				case governedManifestPath:
					return os.ReadFile(governedManifestPath)
				case structureManifestPath:
					return os.ReadFile(structureManifestPath)
				case executionManifestPath:
					return os.ReadFile(executionManifestPath)
				case transformManifestPath:
					return os.ReadFile(transformManifestPath)
				default:
					return nil, errors.New("unexpected manifest")
				}
			}
			stderr.Reset()
			if runManifestPolicy(&stderr, read) == 0 {
				t.Fatalf("changed or missing manifest %s accepted", target)
			}
		}
	}
}
