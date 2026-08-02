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
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSourcePolicySplitInventoryMatches(t *testing.T) {
	t.Parallel()

	findings, err := sourcePolicySplitDeclarationFindings(expectedSplitFiles(), readSourcePolicyFixture)
	if err != nil {
		t.Fatalf("sourcePolicySplitDeclarationFindings() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("sourcePolicySplitDeclarationFindings() = %v", findings)
	}
}

func TestSourcePolicySplitInventoryRejectsDrift(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path string
		edit func([]byte) []byte
		want string
	}{
		"declaration": {
			path: "tools/sourcepolicy/cargo.go",
			edit: func(source []byte) []byte {
				return append(source, []byte("\nvar policyInventoryProbe = 1\n")...)
			},
			want: "source inventory differs",
		},
		"test target": {
			path: "tools/sourcepolicy/cargo_test.go",
			edit: func(source []byte) []byte {
				return bytes.Replace(source, []byte("func TestCargo"), []byte("func CheckCargo"), 1)
			},
			want: "test target inventory differs",
		},
		"fixture": {
			path: sourcePolicyFixturePath,
			edit: func(source []byte) []byte {
				return append(slices.Clone(source), '\n')
			},
			want: "fixture inventory differs",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			readFile := func(file string) ([]byte, error) {
				source, err := readSourcePolicyFixture(file)
				if err != nil || file != test.path {
					return source, err
				}
				return test.edit(source), nil
			}
			findings, err := sourcePolicySplitDeclarationFindings(expectedSplitFiles(), readFile)
			if err != nil {
				t.Fatalf("sourcePolicySplitDeclarationFindings() error = %v", err)
			}
			if !slices.ContainsFunc(findings, func(finding string) bool {
				return strings.Contains(finding, test.want)
			}) {
				t.Fatalf("findings = %v, want %q", findings, test.want)
			}
		})
	}
}

func TestSourcePolicySplitInventoryRejectsRefreshedBaseline(t *testing.T) {
	t.Parallel()

	readFile := func(file string) ([]byte, error) {
		source, err := readSourcePolicyFixture(file)
		if err != nil || file != "tools/sourcepolicy/cargo.go" {
			return source, err
		}
		return append(source, []byte("\nvar policyInventoryProbe = 1\n")...), nil
	}
	baseline := refreshedSourcePolicyBaseline(t, readFile)
	refreshedReader := func(file string) ([]byte, error) {
		if file == sourcePolicyBaselinePath {
			return baseline, nil
		}
		return readFile(file)
	}
	_, err := sourcePolicySplitDeclarationFindings(expectedSplitFiles(), refreshedReader)
	if err == nil || !strings.Contains(err.Error(), "differs from its reviewed form") {
		t.Fatalf("refreshed baseline error = %v", err)
	}
}

func refreshedSourcePolicyBaseline(
	t *testing.T,
	readFile func(string) ([]byte, error),
) []byte {
	t.Helper()
	goFiles := slices.DeleteFunc(expectedSplitFiles(), func(file string) bool {
		return filepath.ToSlash(filepath.Dir(file)) != "tools/sourcepolicy" ||
			filepath.Ext(file) != ".go"
	})
	inventory, err := ownedGoSplitInventoryFor(goFiles, readFile, ownedGoSplitSpec{
		directory: sourcePolicySplitDirectory,
		packages:  []string{"main"},
		owners:    sourcePolicySplitOwners(),
		maxBytes:  maxSourcePolicySplitBytes,
		label:     "source-policy",
	})
	if err != nil {
		t.Fatalf("ownedGoSplitInventoryFor() error = %v", err)
	}
	fixture, err := readFile(sourcePolicyFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fixtureSHA := sha256.Sum256(fixture)
	baseline, err := json.Marshal(sourcePolicySplitBaseline{
		Schema:        sourcePolicyBaselineSchema,
		PackageSHA:    inventory.packages,
		SourceSHA:     inventory.sources,
		TargetSHA:     inventory.targets,
		FixtureSHA256: hex.EncodeToString(fixtureSHA[:]),
	})
	if err != nil {
		t.Fatalf("marshal refreshed baseline: %v", err)
	}
	return baseline
}

func readSourcePolicyFixture(file string) ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
}

func TestSourcePolicySplitInventoryRejectsInvalidBaseline(t *testing.T) {
	t.Parallel()

	for name, baseline := range map[string]string{
		"empty":         "",
		"unknown field": `{"schema_version":"celestia.source-policy.split-inventory.v1","unknown":true}`,
		"placeholder":   `{"schema_version":"celestia.source-policy.split-inventory.v1","package_sha256":"pending"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := readSourcePolicySplitBaseline(func(string) ([]byte, error) {
				return []byte(baseline), nil
			})
			if err == nil {
				t.Fatal("readSourcePolicySplitBaseline() accepted invalid baseline")
			}
		})
	}
}
