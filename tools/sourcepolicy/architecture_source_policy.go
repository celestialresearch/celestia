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
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
)

const (
	sourcePolicySplitDirectory = "tools/sourcepolicy/"
	sourcePolicyBaselinePath   = "policies/source-policy-inventory.json"
	sourcePolicyFixturePath    = "tools/sourcepolicy/testdata/architecture-v1.json"
	sourcePolicyBaselineSchema = "celestia.source-policy.split-inventory.v1"
	maxSourcePolicySplitBytes  = 16 << 20
)

type sourcePolicySplitBaseline struct {
	Schema        string `json:"schema_version"`
	PackageSHA    string `json:"package_sha256"`
	SourceSHA     string `json:"source_sha256"`
	TargetSHA     string `json:"target_sha256"`
	FixtureSHA256 string `json:"fixture_sha256"`
}

func sourcePolicySplitDeclarationFindings(
	files []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	baseline, err := readSourcePolicySplitBaseline(readFile)
	if err != nil {
		return nil, err
	}
	goFiles := slices.DeleteFunc(slices.Clone(files), func(file string) bool {
		return path.Dir(file) != strings.TrimSuffix(sourcePolicySplitDirectory, "/") ||
			path.Ext(file) != ".go"
	})
	inventory, err := ownedGoSplitInventoryFor(goFiles, readFile, ownedGoSplitSpec{
		directory: sourcePolicySplitDirectory,
		packages:  []string{"main"},
		owners:    sourcePolicySplitOwners(),
		maxBytes:  maxSourcePolicySplitBytes,
		label:     "source-policy",
	})
	if err != nil {
		return nil, err
	}
	fixture, err := readFile(sourcePolicyFixturePath)
	if err != nil {
		return nil, fmt.Errorf("read source-policy fixture %q: %w", sourcePolicyFixturePath, quotedDiagnostic(err))
	}
	fixtureSHA := sha256.Sum256(fixture)
	var findings []string
	for label, pair := range map[string][2]string{
		"package, build and owner": {inventory.packages, baseline.PackageSHA},
		"source":                   {inventory.sources, baseline.SourceSHA},
		"test target":              {inventory.targets, baseline.TargetSHA},
		"fixture":                  {hex.EncodeToString(fixtureSHA[:]), baseline.FixtureSHA256},
	} {
		if pair[0] != pair[1] {
			findings = append(findings, fmt.Sprintf(
				"%s: %s inventory differs: %s",
				strings.TrimSuffix(sourcePolicySplitDirectory, "/"), label, pair[0],
			))
		}
	}
	sort.Strings(findings)
	return findings, nil
}

func readSourcePolicySplitBaseline(
	readFile func(string) ([]byte, error),
) (sourcePolicySplitBaseline, error) {
	data, err := readFile(sourcePolicyBaselinePath)
	if err != nil {
		return sourcePolicySplitBaseline{}, fmt.Errorf(
			"read source-policy split inventory: %w", quotedDiagnostic(err),
		)
	}
	if len(data) == 0 || len(data) > maxSourceBytes {
		return sourcePolicySplitBaseline{}, errors.New("source-policy split inventory exceeds its size bound")
	}
	if err := validateJSONStructure(data); err != nil {
		return sourcePolicySplitBaseline{}, fmt.Errorf("source-policy split inventory structure: %w", err)
	}
	var baseline sourcePolicySplitBaseline
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return baseline, fmt.Errorf("decode source-policy split inventory: %w", err)
	}
	if err := expectJSONEnd(decoder); err != nil {
		return baseline, err
	}
	const reviewedSHA256 = "896a5b34c907f8044fc6aa0fdc3f9c6277524824e7a88750c24142cfeb833f5d"
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != reviewedSHA256 ||
		baseline.Schema != sourcePolicyBaselineSchema {
		return baseline, errors.New("source-policy split inventory is invalid or differs from its reviewed form")
	}
	for _, value := range []string{
		baseline.PackageSHA,
		baseline.SourceSHA,
		baseline.TargetSHA,
		baseline.FixtureSHA256,
	} {
		if !validSHA256Hex(value) {
			return baseline, errors.New("source-policy split inventory is invalid or differs from its reviewed form")
		}
	}
	return baseline, nil
}

func sourcePolicySplitOwners() map[string]string {
	owners := make(map[string]string)
	for _, file := range sourcePolicySplitInventory {
		if path.Dir(file) == "." && path.Ext(file) == ".go" {
			owners[file] = strings.TrimSuffix(file, ".go")
		}
	}
	return owners
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sourcePolicySplitFiles() []string {
	return slices.Clone(sourcePolicySplitInventory)
}

var sourcePolicySplitInventory = []string{
	"architecture_attempt_split_test.go",
	"architecture_attempt_split.go",
	"architecture_action_policy_test.go",
	"architecture_action_policy.go",
	"architecture_bounds_test.go",
	"architecture_documentation.go",
	"architecture_documentation_test.go",
	"architecture_evaluation.go",
	"architecture_fixture_evaluation_test.go",
	"architecture_fixtures_test.go",
	"architecture_imports_test.go",
	"architecture_imports.go",
	"architecture_integration_test.go",
	"architecture_inventory.go",
	"architecture_limits_test.go",
	"architecture_limits.go",
	"architecture_operation_split.go",
	"architecture_operation_split_test.go",
	"architecture_ownership.go",
	"architecture_ownership_test.go",
	"architecture_paths.go",
	"architecture_policy.go",
	"architecture_rust_test.go",
	"architecture_rust.go",
	"architecture_scripts_test.go",
	"architecture_scripts.go",
	"architecture_source_policy.go",
	"architecture_source_policy_test.go",
	"architecture_split_test.go",
	"architecture_split.go",
	"architecture_supervision_split.go",
	"architecture_supervision_split_test.go",
	"architecture_values.go",
	"architecture.go",
	"cargo_failures_test.go",
	"cargo_test.go",
	"cargo.go",
	"cargoconfig_failures_test.go",
	"cargoconfig_test.go",
	"cargoconfig.go",
	"doc.go",
	"executable_inventory_test.go",
	"executable_inventory.go",
	"go_policy_fixture_test.go",
	"gobuildtags.go",
	"gocgo_failures_test.go",
	"gocgo_test.go",
	"gocgo.go",
	"goexit.go",
	"goexit_dependency_test.go",
	"goexit_test.go",
	"gofallback.go",
	"goinspect_directives_test.go",
	"goinspect_source_test.go",
	"goinspect.go",
	"golangci.go",
	"goload_failures_test.go",
	"goload_replacement_test.go",
	"goload_test.go",
	"goload_timeout_test.go",
	"goload.go",
	"goskip_test.go",
	"goskip.go",
	"gotarget_constraints_test.go",
	"gotarget_selection_test.go",
	"gotarget_selector_test.go",
	"gotarget_test.go",
	"gotarget.go",
	"gotestmain_test.go",
	"gotestmain.go",
	"inventory_test.go",
	"inventory.go",
	"main_failures_test.go",
	"main_test.go",
	"main.go",
	"manifest_test.go",
	"manifest.go",
	"module_replacement.go",
	"rust_failures_test.go",
	"rust_test.go",
	"rustpolicy.go",
	"rustsyntax.go",
	"scan.go",
	"source_failures_test.go",
	"source_open_other.go",
	"source_open_unix.go",
	"source_test.go",
	"source.go",
	"source_files_test.go",
	"source_files.go",
	"suppression_comments_test.go",
	"suppression_test.go",
	"suppression.go",
	"testdata/architecture-v1.json",
	"testinventory_boundaries_test.go",
	"testinventory_test.go",
	"testinventory.go",
}
