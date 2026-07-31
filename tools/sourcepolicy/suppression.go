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
	"fmt"
	"go/scanner"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

var (
	validNosec = regexp.MustCompile(
		`^[[:space:]]+G[0-9]+(,G[0-9]+)*[[:space:]]+--[[:space:]]+[^[:space:]].*$`,
	)
	validNolint = regexp.MustCompile(
		`^:([a-z0-9][a-z0-9,-]*)[[:space:]]+--[[:space:]]+[^[:space:]].*$`,
	)
	shellcheckDirective = regexp.MustCompile(
		`#[[:space:]]*shellcheck[[:space:]]+disable`,
	)
	gosecDirective = regexp.MustCompile(
		`gosec:`,
	)
	validShellcheck = regexp.MustCompile(
		`^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]+disable[[:space:]]*=[[:space:]]*SC[0-9]+(,SC[0-9]+)*[[:space:]]+#[[:space:]]+[^[:space:]].*$`,
	)
)

var expectedCargoManifests = []string{
	"Cargo.toml",
	"worker/qualification-fixtures/Cargo.toml",
	"worker/url-reference/Cargo.toml",
}

func goSuppressionFindings(path string, source []byte) []string {
	var findings []string
	for _, line := range gosecDirectiveLines(source) {
		findings = append(findings, fmt.Sprintf(
			"%s:%d: invalid gosec suppression", path, line,
		))
	}
	for index, line := range bytes.Split(source, []byte{'\n'}) {
		text := string(line)
		_, nosec, hasNosec := strings.Cut(text, nosecMarker)
		if hasNosec && !validNosec.MatchString(nosec) {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: invalid gosec suppression", path, index+1,
			))
		}
		_, nolint, hasNolint := strings.Cut(text, nolintMarker)
		if hasNolint {
			match := validNolint.FindStringSubmatch(nolint)
			if len(match) != 2 || contains(
				strings.Split(match[1], ","), "all",
			) {
				findings = append(findings, fmt.Sprintf(
					"%s:%d: invalid golangci-lint suppression",
					path,
					index+1,
				))
			}
		}
	}
	return findings
}

func gosecDirectiveLines(source []byte) []int {
	files := token.NewFileSet()
	file := files.AddFile("source.go", -1, len(source))
	var lexer scanner.Scanner
	lexer.Init(file, source, nil, scanner.ScanComments)
	var lines []int
	for {
		position, kind, literal := lexer.Scan()
		if kind == token.EOF {
			return lines
		}
		if kind == token.COMMENT && gosecDirective.MatchString(literal) {
			lines = append(lines, files.Position(position).Line)
		}
	}
}

func shellSuppressionFindings(path string, source []byte) []string {
	var findings []string
	for index, line := range bytes.Split(source, []byte{'\n'}) {
		if shellcheckDirective.Match(line) && !validShellcheck.Match(line) {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: invalid ShellCheck suppression", path, index+1,
			))
		}
	}
	return findings
}

func golangciConfigFindings(path string, source []byte) []string {
	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		return []string{fmt.Sprintf(
			"%s: parse golangci-lint configuration: %v",
			path,
			err,
		)}
	}
	var findings []string
	for _, owner := range []string{"linters", "formatters"} {
		if _, exists := nestedTable(document, owner)["exclusions"]; exists {
			findings = append(findings, fmt.Sprintf(
				"%s: golangci-lint %s exclusions are prohibited",
				path,
				owner,
			))
		}
	}
	return findings
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
		return nil
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
	if workspace == nil {
		return nil
	}
	var findings []string
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
	if cargoHasLibrarySource(files) {
		findings = append(
			findings,
			"Cargo.toml: Cargo library targets are prohibited",
		)
	}
	return findings
}

func cargoHasLibrarySource(files []string) bool {
	return slices.ContainsFunc(files, func(path string) bool {
		slashPath := filepath.ToSlash(path)
		return slashPath == "src/lib.rs" ||
			strings.HasSuffix(slashPath, "/src/lib.rs")
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
	if packageTable := nestedTable(document, "package"); packageTable != nil {
		for _, setting := range []string{
			"autolib",
			"autobins",
			"autoexamples",
			"autotests",
			"autobenches",
		} {
			if enabled, exists := packageTable[setting]; exists &&
				enabled != true {
				findings = append(findings, fmt.Sprintf(
					"%s: Cargo automatic target discovery must remain enabled",
					path,
				))
			}
		}
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

func cargoConfigFindings(path string, source []byte) []string {
	var document map[string]any
	_, err := toml.Decode(string(source), &document)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Cargo configuration: %v", path, err)}
	}
	var findings []string
	inspectCargoConfig(path, "", document, &findings)
	slices.Sort(findings)
	return findings
}

func inspectCargoConfig(
	path, parent string,
	value any,
	findings *[]string,
) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if cargoExecutionOverride(parent, key) {
				*findings = append(*findings, fmt.Sprintf(
					"%s: Cargo execution override is prohibited: %s", path, key,
				))
				continue
			}
			if key == "rustflags" || key == "rustdocflags" {
				if !cargoFlagsApproved(key, child) {
					*findings = append(*findings, fmt.Sprintf(
						"%s: Cargo %s are not approved", path, key,
					))
				}
				continue
			}
			inspectCargoConfig(path, key, child, findings)
		}
	case []map[string]any:
		for _, child := range typed {
			inspectCargoConfig(path, parent, child, findings)
		}
	}
}

func cargoExecutionOverride(parent, key string) bool {
	switch key {
	case "linker", "links", "runner", "rustc", "rustdoc", "rustc-wrapper",
		"rustc-workspace-wrapper", "warnings":
		return true
	}
	if parent == "" {
		return cargoRootOverride(key)
	}
	return parent == "build" &&
		(key == "build-dir" || key == "target" || key == "target-dir")
}

func cargoRootOverride(key string) bool {
	switch key {
	case "alias", "credential-alias", "env", "include", "patch", "paths",
		"profile", "replace", "source":
		return true
	default:
		return false
	}
}

func cargoFlagsApproved(key string, value any) bool {
	flags, valid := cargoFlags(value)
	if !valid {
		return false
	}
	if len(flags) == 0 {
		return true
	}
	return key == "rustflags" &&
		slices.Equal(flags, []string{"-C", "link-arg=/Brepro"})
}

func cargoFlags(value any) ([]string, bool) {
	switch typed := value.(type) {
	case string:
		return strings.Fields(typed), true
	case []any:
		flags := make([]string, 0, len(typed))
		for _, item := range typed {
			flag, ok := item.(string)
			if !ok {
				return nil, false
			}
			flags = append(flags, flag)
		}
		return flags, true
	default:
		return nil, false
	}
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
