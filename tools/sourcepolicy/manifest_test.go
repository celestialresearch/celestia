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
	"errors"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

type policyTestSplitManifest struct {
	CanonicalState []string `json:"canonical_state"`
	Resources      []struct {
		ID    string `json:"id"`
		Bound string `json:"bound"`
	} `json:"resources"`
	Invariants []struct {
		ID        string `json:"id"`
		Statement string `json:"statement"`
	} `json:"invariants"`
	Success string `json:"success_semantics"`
}

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

func TestAssuranceSplitManifestPreservesCustody(t *testing.T) {
	t.Chdir("../..")
	data, err := os.ReadFile(assuranceSplitPath)
	if err != nil {
		t.Fatalf("read Assurance split manifest: %v", err)
	}
	var manifest struct {
		Owner              string `json:"owner"`
		ProductionControls []struct {
			Owner string `json:"owner"`
		} `json:"production_controls"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode Assurance split manifest: %v", err)
	}
	if manifest.Owner != "internal/architecturecheck" {
		t.Fatalf("manifest owner = %q", manifest.Owner)
	}
	if len(manifest.ProductionControls) != 1 ||
		manifest.ProductionControls[0].Owner !=
			"source-policy exact CEL-SPLIT-007 declaration digest" {
		t.Fatalf("Product controls claim Assurance custody: %+v", manifest.ProductionControls)
	}
	if bytes.Contains(data, []byte("source-policy Assurance")) {
		t.Fatal("Product claims Assurance inventory ownership")
	}
}

func TestPolicyTestSplitManifestMatchesVerificationDriver(t *testing.T) {
	t.Chdir("../..")
	data, err := os.ReadFile(policyTestSplitPath)
	if err != nil {
		t.Fatalf("read policy-test split manifest: %v", err)
	}
	var manifest policyTestSplitManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode policy-test split manifest: %v", err)
	}
	driver, err := os.ReadFile(".github/scripts/verification_test.sh")
	if err != nil {
		t.Fatalf("read verification driver: %v", err)
	}
	got := verificationDriverFamilies(t, driver)
	want := []string{
		"lint_test.sh", "action_test.sh", "devcheck_config_test.sh",
		"rust_config_test.sh", "rust_integration_test.sh", "rust_artefact_test.sh",
		"coverage_test.sh", "source_policy_test.sh", "licence_test.sh",
		"release_artefact_test.sh",
	}
	if !equalStrings(got, want) {
		t.Fatalf("verification driver families = %q, want %q", got, want)
	}
	assertVerificationFamilyContract(t, manifest)
}

func assertVerificationFamilyContract(
	t *testing.T,
	manifest policyTestSplitManifest,
) {
	t.Helper()
	const wantState = "The verification driver executes the lint, action, development-check configuration, Rust configuration, Rust integration, Rust artefact, coverage, source policy, licence and release artefact families in that exact order"
	if !slices.Contains(manifest.CanonicalState, wantState) {
		t.Fatalf("manifest lacks canonical family order %q", wantState)
	}
	const executionRecordID = "CEL-SPLIT-006-RESOURCE-003"
	foundResource := false
	for _, resource := range manifest.Resources {
		if resource.ID == executionRecordID {
			foundResource = true
			if resource.Bound != "At most ten newline-delimited declared family names" {
				t.Fatalf("execution-record bound = %q", resource.Bound)
			}
			break
		}
	}
	if !foundResource {
		t.Fatalf("manifest lacks resource %s", executionRecordID)
	}
	const familyInvariantID = "CEL-SPLIT-006-INV-002"
	for _, invariant := range manifest.Invariants {
		if invariant.ID == familyInvariantID {
			if invariant.Statement != "The driver executes exactly ten declared executable verification families serially in the declared order" {
				t.Fatalf("family invariant = %q", invariant.Statement)
			}
			if manifest.Success != "Accepted means the exact action-test ownership and ten-family shell split preserve targets, order, executable modes, serial execution, labels, isolation, cleanup and failure propagation" {
				t.Fatalf("success semantics = %q", manifest.Success)
			}
			return
		}
	}
	t.Fatalf("manifest lacks invariant %s", familyInvariantID)
}

func verificationDriverFamilies(t *testing.T, source []byte) []string {
	t.Helper()
	const start = "families=(\n"
	const end = ")\n\nfixture_mode="
	_, after, found := bytes.Cut(source, []byte(start))
	if !found {
		t.Fatal("verification driver lacks the family declaration")
	}
	block, _, found := bytes.Cut(after, []byte(end))
	if !found {
		t.Fatal("verification driver has an unterminated family declaration")
	}
	block = bytes.TrimSuffix(block, []byte{'\n'})
	lines := bytes.Split(block, []byte{'\n'})
	families := make([]string, 0, len(lines))
	for _, line := range lines {
		family := strings.TrimSpace(string(line))
		if family == "" || !strings.HasSuffix(family, "_test.sh") {
			t.Fatalf("invalid verification family declaration %q", line)
		}
		families = append(families, family)
	}
	return families
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
		governedManifestPath: func() ([]byte, error) { return os.ReadFile(governedManifestPath) },
		performanceManifestPath: func() ([]byte, error) {
			return os.ReadFile(performanceManifestPath)
		},
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
		freezeSplitPath:       func() ([]byte, error) { return os.ReadFile(freezeSplitPath) },
	}
}
