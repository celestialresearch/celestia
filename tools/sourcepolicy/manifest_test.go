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
	"sort"
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
	paths := reviewedManifestPaths()
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

func reviewedManifestPaths() []string {
	readers := reviewedManifestReaders()
	paths := make([]string, 0, len(readers))
	for path := range readers {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func readReviewedManifest(path string) ([]byte, error) {
	read, ok := reviewedManifestReaders()[path]
	if !ok {
		return nil, errors.New("unexpected manifest")
	}
	return read()
}

func reviewedManifestReaders() map[string]func() ([]byte, error) {
	return map[string]func() ([]byte, error){
		governedManifestPath:  func() ([]byte, error) { return os.ReadFile(governedManifestPath) },
		structureManifestPath: func() ([]byte, error) { return os.ReadFile(structureManifestPath) },
		executionManifestPath: func() ([]byte, error) { return os.ReadFile(executionManifestPath) },
		transformManifestPath: func() ([]byte, error) { return os.ReadFile(transformManifestPath) },
		protocolManifestPath:  func() ([]byte, error) { return os.ReadFile(protocolManifestPath) },
		admissionManifestPath: func() ([]byte, error) { return os.ReadFile(admissionManifestPath) },
		attemptManifestPath:   func() ([]byte, error) { return os.ReadFile(attemptManifestPath) },
		operationManifestPath: func() ([]byte, error) { return os.ReadFile(operationManifestPath) },
		layoutManifestPath:    func() ([]byte, error) { return os.ReadFile(layoutManifestPath) },
		splitManifestPath:     func() ([]byte, error) { return os.ReadFile(splitManifestPath) },
		attemptSplitPath:      func() ([]byte, error) { return os.ReadFile(attemptSplitPath) },
		supervisionSplitPath:  func() ([]byte, error) { return os.ReadFile(supervisionSplitPath) },
		operationSplitPath:    func() ([]byte, error) { return os.ReadFile(operationSplitPath) },
		sourcePolicySplitPath: func() ([]byte, error) { return os.ReadFile(sourcePolicySplitPath) },
		policyTestSplitPath:   func() ([]byte, error) { return os.ReadFile(policyTestSplitPath) },
		assuranceSplitPath:    func() ([]byte, error) { return os.ReadFile(assuranceSplitPath) },
	}
}
