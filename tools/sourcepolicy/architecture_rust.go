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
	"fmt"
	"slices"

	"github.com/BurntSushi/toml"
)

type architectureRustPackage struct {
	manifest       string
	name           string
	implicitTarget bool
	targets        []architectureRustTarget
}

type architectureRustTarget struct {
	name string
	path string
}

func expectedArchitectureRustPackages() []architectureRustPackage {
	return []architectureRustPackage{
		{
			manifest:       "worker/url-reference/Cargo.toml",
			name:           "celestia-url-reference",
			implicitTarget: true,
			targets: []architectureRustTarget{
				{name: "celestia-url-reference", path: "src/main.rs"},
			},
		},
		{
			manifest: "worker/qualification-fixtures/Cargo.toml",
			name:     "celestia-qualification-fixtures",
			targets: []architectureRustTarget{
				{name: "celestia-blocked-input-worker", path: "src/bin/blocked_input.rs"},
				{name: "celestia-hostile-worker", path: "src/bin/hostile.rs"},
			},
		},
	}
}

func architectureRustTargetFindings(
	readFile func(string) ([]byte, error),
) ([]string, error) {
	var findings []string
	for _, expected := range expectedArchitectureRustPackages() {
		source, err := readFile(expected.manifest)
		if err != nil {
			return nil, fmt.Errorf("read Rust package %s: %w", expected.manifest, err)
		}
		actual, err := decodeArchitectureRustPackage(source, expected)
		if err != nil {
			return nil, fmt.Errorf("decode Rust package %s: %w", expected.manifest, err)
		}
		if actual.name != expected.name || !slices.Equal(actual.targets, expected.targets) {
			findings = append(
				findings,
				expected.manifest+": Rust targets contradict architecture policy",
			)
		}
	}
	slices.Sort(findings)
	return findings, nil
}

func decodeArchitectureRustPackage(
	source []byte,
	expected architectureRustPackage,
) (architectureRustPackage, error) {
	var document map[string]any
	if _, err := toml.Decode(string(source), &document); err != nil {
		return architectureRustPackage{}, err
	}
	name := architectureRustPackageName(document)
	targets, valid := architectureRustTargets(document["bin"])
	if !valid || architectureRustHasExtraTargets(document) {
		return architectureRustPackage{name: name}, nil
	}
	if len(targets) == 0 && expected.implicitTarget {
		targets = slices.Clone(expected.targets)
	}
	slices.SortFunc(targets, func(left, right architectureRustTarget) int {
		if left.name != right.name {
			if left.name < right.name {
				return -1
			}
			return 1
		}
		if left.path < right.path {
			return -1
		}
		if left.path > right.path {
			return 1
		}
		return 0
	})
	return architectureRustPackage{name: name, targets: targets}, nil
}

func architectureRustPackageName(document map[string]any) string {
	name, valid := nestedTable(document, "package")["name"].(string)
	if !valid {
		return ""
	}
	return name
}

func architectureRustHasExtraTargets(document map[string]any) bool {
	for _, target := range []string{"lib", "example", "test", "bench"} {
		if len(cargoTargetTables(document[target])) != 0 {
			return true
		}
	}
	return false
}

func architectureRustTargets(value any) ([]architectureRustTarget, bool) {
	tables := cargoTargetTables(value)
	targets := make([]architectureRustTarget, 0, len(tables))
	for _, table := range tables {
		name, nameOK := table["name"].(string)
		path, pathOK := table["path"].(string)
		if !nameOK || !pathOK {
			return nil, false
		}
		targets = append(targets, architectureRustTarget{name: name, path: path})
	}
	return targets, true
}
