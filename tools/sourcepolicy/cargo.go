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
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

var expectedCargoManifests = []string{
	"Cargo.toml",
	"worker/qualification-fixtures/Cargo.toml",
	"worker/url-reference/Cargo.toml",
}

func cargoLintFindings(path string, source []byte) []string {
	var document map[string]any
	_, err := toml.Decode(string(source), &document)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Cargo manifest: %v", path, err)}
	}
	var findings []string
	for _, key := range []string{"patch", "replace"} {
		if _, exists := document[key]; exists {
			findings = append(findings, fmt.Sprintf(
				"%s: Cargo source override is prohibited: %s", path, key,
			))
		}
	}
	findings = append(findings, cargoTestDiscoveryFindings(path, document)...)
	if cargoOptionalDependency(document) {
		findings = append(findings, fmt.Sprintf(
			"%s: optional Cargo dependencies require an explicit test matrix",
			path,
		))
	}
	for _, root := range []string{"lints", "workspace.lints"} {
		table := nestedTable(document, strings.Split(root, ".")...)
		for namespace, value := range table {
			lints, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for rule, value := range lints {
				if lintLevel(value) != "allow" {
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"%s: Cargo lint allowances are prohibited: %s %q",
					path,
					namespace,
					rule,
				))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

func cargoOptionalDependency(document map[string]any) bool {
	for key := range document {
		if strings.HasSuffix(key, "dependencies") {
			for _, dependency := range nestedTable(document, key) {
				table, ok := dependency.(map[string]any)
				if ok && table["optional"] == true {
					return true
				}
			}
		}
		if key == "workspace" &&
			cargoOptionalDependency(nestedTable(document, key)) {
			return true
		}
		if key == "target" {
			for _, target := range nestedTable(document, key) {
				table, ok := target.(map[string]any)
				if ok && cargoOptionalDependency(table) {
					return true
				}
			}
		}
	}
	return false
}

func cargoWorkspaceInventoryFindings(
	files []string,
	readFile func(string) ([]byte, error),
) []string {
	if !slices.Contains(files, "Cargo.toml") {
		return []string{"Cargo.toml: missing governed Cargo workspace"}
	}
	source, err := readFile("Cargo.toml")
	if err != nil {
		return []string{fmt.Sprintf("Cargo.toml: %v", err)}
	}
	var document map[string]any
	if _, err := toml.Decode(string(source), &document); err != nil {
		return nil
	}
	workspace := nestedTable(document, "workspace")
	var findings []string
	if workspace == nil {
		findings = append(findings, "Cargo.toml: missing governed workspace table")
	} else {
		if !cargoStringListEquals(
			workspace["members"],
			[]string{"worker/url-reference"},
		) {
			findings = append(findings, "Cargo.toml: unexpected workspace members")
		}
		if !cargoStringListEquals(
			workspace["exclude"],
			[]string{"worker/qualification-fixtures"},
		) {
			findings = append(findings, "Cargo.toml: unexpected workspace exclusions")
		}
	}
	var manifests []string
	for _, path := range files {
		if filepath.Base(path) == "Cargo.toml" {
			manifests = append(manifests, filepath.ToSlash(path))
		}
	}
	slices.Sort(manifests)
	if !slices.Equal(manifests, expectedCargoManifests) {
		findings = append(findings, "Cargo.toml: unexpected Cargo manifest inventory")
	}
	if cargoHasLibrarySource(files, nestedTable(document, "package") != nil) {
		findings = append(
			findings,
			"Cargo.toml: Cargo library targets are prohibited",
		)
	}
	return findings
}

func cargoHasLibrarySource(files []string, rootPackage bool) bool {
	manifests := expectedCargoManifests[1:]
	if rootPackage {
		manifests = expectedCargoManifests
	}
	return slices.ContainsFunc(manifests, func(manifest string) bool {
		directory := filepath.ToSlash(filepath.Dir(manifest))
		path := "src/lib.rs"
		if directory != "." {
			path = directory + "/" + path
		}
		return slices.ContainsFunc(files, func(file string) bool {
			return strings.EqualFold(filepath.ToSlash(file), path)
		})
	})
}

func cargoStringListEquals(value any, expected []string) bool {
	values, ok := value.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return false
		}
		actual = append(actual, text)
	}
	return slices.Equal(actual, expected)
}

func cargoTestDiscoveryFindings(
	path string,
	document map[string]any,
) []string {
	var findings []string
	if features := nestedTable(document, "features"); len(features) > 0 {
		findings = append(findings, fmt.Sprintf(
			"%s: Cargo package features require an explicit test matrix", path,
		))
	}
	if profile := nestedTable(document, "profile"); len(profile) > 0 {
		findings = append(findings, fmt.Sprintf(
			"%s: Cargo profile overrides are prohibited", path,
		))
	}
	if document["lib"] != nil {
		findings = append(findings, fmt.Sprintf(
			"%s: Cargo library targets are prohibited", path,
		))
	}
	for _, key := range []string{"bin", "example", "test", "bench"} {
		for _, target := range cargoTargetTables(document[key]) {
			if cargoTargetOmitsTests(target) {
				findings = append(findings, fmt.Sprintf(
					"%s: Cargo target %s may omit tests", path, key,
				))
			}
		}
	}
	return findings
}

func cargoTargetTables(value any) []map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return []map[string]any{typed}
	case []map[string]any:
		return typed
	default:
		return nil
	}
}

func cargoTargetOmitsTests(target map[string]any) bool {
	if enabled, exists := target["test"]; exists && enabled != true {
		return true
	}
	if harness, exists := target["harness"]; exists && harness != true {
		return true
	}
	if doctest, exists := target["doctest"]; exists && doctest != true {
		return true
	}
	features, gated := target["required-features"].([]any)
	return gated && len(features) > 0
}

func nestedTable(document map[string]any, keys ...string) map[string]any {
	current := document
	for _, key := range keys {
		value, ok := current[key].(map[string]any)
		if !ok {
			return nil
		}
		current = value
	}
	return current
}

func lintLevel(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.ToLower(typed)
	case map[string]any:
		level, ok := typed["level"].(string)
		if !ok {
			return ""
		}
		return strings.ToLower(level)
	default:
		return ""
	}
}
