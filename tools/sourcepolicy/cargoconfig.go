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
	"strings"

	"github.com/BurntSushi/toml"
)

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
