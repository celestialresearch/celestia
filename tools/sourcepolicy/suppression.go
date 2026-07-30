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
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
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
	validShellcheck = regexp.MustCompile(
		`^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]+disable[[:space:]]*=[[:space:]]*SC[0-9]+(,SC[0-9]+)*[[:space:]]+#[[:space:]]+[^[:space:]].*$`,
	)
)

func goSuppressionFindings(path string, source []byte) []string {
	var findings []string
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

func cargoLintFindings(path string, source []byte) []string {
	var document map[string]any
	_, err := toml.Decode(string(source), &document)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Cargo manifest: %v", path, err)}
	}
	var findings []string
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
