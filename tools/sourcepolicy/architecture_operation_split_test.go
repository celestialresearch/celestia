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
	"maps"
	"strings"
	"testing"
)

func TestArchitecturePolicyRejectsOperationSplitDrift(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	for name, fixture := range operationSplitDriftFixtures() {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			if status := runArchitecturePolicy(
				&stderr, func() ([]string, error) { return files, nil },
				sourceExecutables, fixture,
			); status == 0 || !strings.Contains(stderr.String(), "internal/operation/urlreference") {
				t.Fatalf("status = %d, stderr = %q", status, stderr.String())
			}
		})
	}
}

func TestOperationSplitInventoryBindsOwner(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	want, err := operationSplitInventoryFor(files, readSource, operationSplitOwners)
	if err != nil {
		t.Fatalf("baseline inventory: %v", err)
	}
	owners := map[string]string{}
	maps.Copy(owners, operationSplitOwners)
	owners["evidence_windows.go"] = "projection"
	got, err := operationSplitInventoryFor(files, readSource, owners)
	if err != nil {
		t.Fatalf("mutated inventory: %v", err)
	}
	if got.packages == want.packages {
		t.Fatal("owner mutation survived")
	}
}

func operationSplitDriftFixtures() map[string]func(string) ([]byte, error) {
	return map[string]func(string) ([]byte, error){
		"declaration": mutatingSourceReader(
			operationSplitDirectory+"operation.go", nil,
			[]byte("\nfunc ungovernedOperationDeclaration() {}\n"),
		),
		"build constraint": mutatingSourceReader(
			operationSplitDirectory+"operation_windows.go",
			[]byte("//go:build windows && amd64"),
			[]byte("//go:build linux && amd64"),
		),
		"test target": mutatingSourceReader(
			operationSplitDirectory+"operation_unsupported_test.go",
			[]byte("func TestOperationFailsClosed("),
			[]byte("func TestOperationRefusesPlatform("),
		),
	}
}

func mutatingSourceReader(file string, old, replacement []byte) func(string) ([]byte, error) {
	return func(candidate string) ([]byte, error) {
		source, err := readSource(candidate)
		if err != nil || candidate != file {
			return source, err
		}
		if old == nil {
			return append(source, replacement...), nil
		}
		if bytes.Count(source, old) != 1 {
			return nil, errors.New("mutation target is not unique")
		}
		return bytes.Replace(source, old, replacement, 1), nil
	}
}
