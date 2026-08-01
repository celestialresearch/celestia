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
	manifest string
	name     string
	targets  []architectureRustTarget
}

type architectureRustTarget struct {
	kind string
	name string
	path string
}

func expectedArchitectureRustPackages() []architectureRustPackage {
	return []architectureRustPackage{
		{
			manifest: "worker/url-reference/Cargo.toml",
			name:     "celestia-url-reference",
			targets: []architectureRustTarget{
				{kind: "bin", name: "celestia-url-reference", path: "src/main.rs"},
				{kind: "test", name: "process", path: "tests/process.rs"},
			},
		},
		{
			manifest: "worker/qualification-fixtures/Cargo.toml",
			name:     "celestia-qualification-fixtures",
			targets: []architectureRustTarget{
				{kind: "bin", name: "celestia-blocked-input-worker", path: "src/bin/blocked_input.rs"},
				{kind: "bin", name: "celestia-hostile-worker", path: "src/bin/hostile.rs"},
			},
		},
	}
}

func architectureRustTargetFindings(
	readFile func(string) ([]byte, error),
) ([]string, error) {
	var findings []string
	workspace, err := readFile("Cargo.toml")
	if err != nil {
		return nil, fmt.Errorf("read Rust workspace: %w", err)
	}
	var workspaceDocument map[string]any
	if _, err := toml.Decode(string(workspace), &workspaceDocument); err != nil {
		return nil, fmt.Errorf("decode Rust workspace: %w", err)
	}
	if _, exists := workspaceDocument["package"]; exists {
		findings = append(findings, "Cargo.toml: workspace root package is prohibited")
	}
	for _, expected := range expectedArchitectureRustPackages() {
		source, err := readFile(expected.manifest)
		if err != nil {
			return nil, fmt.Errorf("read Rust package %s: %w", expected.manifest, err)
		}
		actual, err := decodeArchitectureRustPackage(source)
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

func decodeArchitectureRustPackage(source []byte) (architectureRustPackage, error) {
	var document map[string]any
	if _, err := toml.Decode(string(source), &document); err != nil {
		return architectureRustPackage{}, err
	}
	name := architectureRustPackageName(document)
	var targets []architectureRustTarget
	valid := true
	for _, kind := range []string{"bin", "test"} {
		decoded, decodedOK := architectureRustTargets(document[kind], kind)
		targets = append(targets, decoded...)
		valid = valid && decodedOK
	}
	if !valid || architectureRustAutomaticTargets(document) ||
		architectureRustHasExtraTargets(document) || architectureRustHasBuildScript(document) {
		return architectureRustPackage{name: name}, nil
	}
	slices.SortFunc(targets, func(left, right architectureRustTarget) int {
		if left.kind != right.kind {
			if left.kind < right.kind {
				return -1
			}
			return 1
		}
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

func architectureRustHasBuildScript(document map[string]any) bool {
	_, exists := nestedTable(document, "package")["build"]
	return exists
}

func architectureRustAutomaticTargets(document map[string]any) bool {
	pack := nestedTable(document, "package")
	for _, setting := range []string{"autobins", "autotests"} {
		value, exists := pack[setting]
		if !exists || value != false {
			return true
		}
	}
	return false
}

func architectureRustPackageName(document map[string]any) string {
	name, valid := nestedTable(document, "package")["name"].(string)
	if !valid {
		return ""
	}
	return name
}

func architectureRustHasExtraTargets(document map[string]any) bool {
	for _, target := range []string{"lib", "example", "bench"} {
		if len(cargoTargetTables(document[target])) != 0 {
			return true
		}
	}
	return false
}

func architectureRustTargets(value any, kind string) ([]architectureRustTarget, bool) {
	if value == nil {
		return nil, true
	}
	tables := cargoTargetTables(value)
	if len(tables) == 0 {
		return nil, false
	}
	targets := make([]architectureRustTarget, 0, len(tables))
	for _, table := range tables {
		name, nameOK := table["name"].(string)
		path, pathOK := table["path"].(string)
		if !nameOK || !pathOK {
			return nil, false
		}
		targets = append(targets, architectureRustTarget{kind: kind, name: name, path: path})
	}
	return targets, true
}
