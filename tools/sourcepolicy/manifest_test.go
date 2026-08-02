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

	manifests := reviewedManifestContents(t)
	var stderr bytes.Buffer
	if runManifestPolicy(&stderr, os.ReadFile) != 0 {
		t.Fatalf("reviewed manifests rejected: %s", stderr.String())
	}
	for target := range manifests {
		for _, missing := range []bool{false, true} {
			read := func(name string) ([]byte, error) {
				if name == target {
					if missing {
						return nil, errors.New("missing")
					}
					return []byte(`{"schema_version":"changed"}`), nil
				}
				data, ok := manifests[name]
				if !ok {
					return nil, errors.New("unexpected manifest")
				}
				return data, nil
			}
			stderr.Reset()
			if runManifestPolicy(&stderr, read) == 0 {
				t.Fatalf("changed or missing manifest %s accepted", target)
			}
		}
	}
}

func reviewedManifestContents(t *testing.T) map[string][]byte {
	t.Helper()
	paths := []string{
		governedManifestPath, structureManifestPath, executionManifestPath,
		transformManifestPath, protocolManifestPath, admissionManifestPath,
		attemptManifestPath, operationManifestPath, layoutManifestPath,
		splitManifestPath,
	}
	manifests := make(map[string][]byte, len(paths))
	for _, path := range paths {
		data, err := readReviewedManifest(path)
		if err != nil {
			t.Fatalf("read manifest %s: %v", path, err)
		}
		manifests[path] = data
	}
	return manifests
}

func readReviewedManifest(path string) ([]byte, error) {
	switch path {
	case governedManifestPath:
		return os.ReadFile(governedManifestPath)
	case structureManifestPath:
		return os.ReadFile(structureManifestPath)
	case executionManifestPath:
		return os.ReadFile(executionManifestPath)
	case transformManifestPath:
		return os.ReadFile(transformManifestPath)
	case protocolManifestPath:
		return os.ReadFile(protocolManifestPath)
	case admissionManifestPath:
		return os.ReadFile(admissionManifestPath)
	case attemptManifestPath:
		return os.ReadFile(attemptManifestPath)
	case operationManifestPath:
		return os.ReadFile(operationManifestPath)
	case layoutManifestPath:
		return os.ReadFile(layoutManifestPath)
	case splitManifestPath:
		return os.ReadFile(splitManifestPath)
	default:
		return nil, errors.New("unexpected manifest")
	}
}
