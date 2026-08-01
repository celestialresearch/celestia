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
	"testing"
)

func TestArchitecturePolicyAcceptsRepository(t *testing.T) {
	t.Chdir("../..")
	var stderr bytes.Buffer
	if status := runArchitecturePolicy(
		&stderr, sourceFiles, sourceExecutables, readSource,
	); status != 0 {
		t.Fatalf("runArchitecturePolicy() = %d: %s", status, stderr.String())
	}
}

func TestArchitecturePolicyRejectsModuleReplacement(t *testing.T) {
	t.Chdir("../..")

	var stderr bytes.Buffer
	read := func(path string) ([]byte, error) {
		if path == "go.mod" {
			return []byte("module celestia.research/celestia\n\ngo 1.26.5\n\nreplace mirror.invalid/assurance => celestia.research/assurance v1.0.0\n"), nil
		}
		return readSource(path)
	}
	status := runArchitecturePolicy(
		&stderr, sourceFiles, sourceExecutables, read,
	)
	if status == 0 || !bytes.Contains(stderr.Bytes(), []byte("replacements are prohibited")) {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
}

func TestArchitecturePolicyBindsMigrationReasons(t *testing.T) {
	t.Parallel()

	policy := validArchitectureFixturePolicy()
	policy.MigrationRoots[0].Reason = "different reason"
	if err := validateArchitecturePolicy(policy); err == nil {
		t.Fatal("validateArchitecturePolicy() accepted a changed migration reason")
	}
}

func TestArchitecturePolicyRejectsInfrastructureFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		inventory    func() ([]string, error)
		read         func(string) ([]byte, error)
		wantFragment string
	}{
		"inventory": {
			inventory:    func() ([]string, error) { return nil, errors.New("inventory failure") },
			wantFragment: "inventory architecture",
		},
		"policy": {
			inventory:    func() ([]string, error) { return nil, nil },
			read:         func(string) ([]byte, error) { return nil, errors.New("read failure") },
			wantFragment: "read architecture policy",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if status := runArchitecturePolicy(
				&stderr, test.inventory, noExecutableSources, test.read,
			); status == 0 || !bytes.Contains(stderr.Bytes(), []byte(test.wantFragment)) {
				t.Fatalf("status = %d, stderr = %q", status, stderr.String())
			}
		})
	}
}

func noExecutableSources([]string) ([]string, error) {
	return nil, nil
}

func TestArchitecturePolicyRejectsJSONBoundaries(t *testing.T) {
	t.Parallel()

	valid, err := json.Marshal(validArchitectureFixturePolicy())
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		nil,
		append(valid, []byte("{}")...),
		[]byte(`{"schema_version":"one","schema_version":"two"}`),
		[]byte("[" + string(bytes.Repeat([]byte("["), maxArchitectureDepth+1)) +
			string(bytes.Repeat([]byte("]"), maxArchitectureDepth+2))),
		[]byte(`{"unknown":true}`),
	}
	for _, data := range tests {
		if _, err := decodeArchitecturePolicy(data); err == nil {
			t.Fatalf("decodeArchitecturePolicy(%q) succeeded", data)
		}
	}
}
