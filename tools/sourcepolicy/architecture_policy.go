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
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	architectureSchema       = "celestia.production.architecture.v1"
	architectureBaseCommit   = "ea8f840aa230f0498f82f3cd00dca22760cf6020"
	architectureModule       = "celestia.research/celestia"
	architectureCurrentSlice = "CEL-STRUCT-005"
	architectureInventory    = "sha256-lf-paths-v1"
	maxArchitectureDepth     = 64
)

type architecturePolicy struct {
	Schema          string               `json:"schema_version"`
	CurrentSlice    string               `json:"current_slice"`
	BaseCommit      string               `json:"base_commit"`
	ModulePath      string               `json:"module_path"`
	InventoryFormat string               `json:"inventory_format"`
	RootDirectories []string             `json:"allowed_root_directories"`
	RootFiles       []string             `json:"allowed_root_files"`
	Prohibited      []string             `json:"prohibited_segments"`
	Packages        []string             `json:"declared_packages"`
	RustPackages    []string             `json:"declared_rust_packages"`
	Scripts         []string             `json:"declared_scripts"`
	Commands        []string             `json:"declared_commands"`
	FileExceptions  []architectureExcept `json:"file_exceptions"`
	ImportRules     []string             `json:"forbidden_import_rules"`
	ProhibitedPaths []string             `json:"prohibited_paths"`
}

type architectureExcept struct {
	Path    string `json:"path"`
	Owner   string `json:"owner"`
	Reason  string `json:"reason"`
	Removal string `json:"removal_condition"`
	Expiry  string `json:"expires_at_completion"`
}

func decodeArchitecturePolicy(data []byte) (architecturePolicy, error) {
	var policy architecturePolicy
	if len(data) == 0 || len(data) > maxSourceBytes {
		return policy, errors.New("architecture policy exceeds its size bound")
	}
	if err := validateJSONStructure(data); err != nil {
		return policy, fmt.Errorf("architecture policy structure: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, fmt.Errorf("decode architecture policy: %w", err)
	}
	if err := expectJSONEnd(decoder); err != nil {
		return policy, err
	}
	if err := validateArchitecturePolicy(policy); err != nil {
		return policy, err
	}
	return policy, nil
}

func expectJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("architecture policy contains trailing data")
	}
	return nil
}

func validateJSONStructure(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	return scanJSONValue(decoder, 0)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxArchitectureDepth {
		return errors.New("JSON nesting exceeds the limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		if err := scanJSONObject(decoder, depth); err != nil {
			return err
		}
	case '[':
		if err := scanJSONArray(decoder, depth); err != nil {
			return err
		}
	default:
		return errors.New("architecture policy contains an invalid delimiter")
	}
	_, err = decoder.Token()
	return err
}

func scanJSONObject(decoder *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("architecture policy contains a non-string key")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = struct{}{}
		if err := scanJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func scanJSONArray(decoder *json.Decoder, depth int) error {
	for decoder.More() {
		if err := scanJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateArchitecturePolicy(policy architecturePolicy) error {
	if !validArchitectureIdentity(policy) || !validArchitectureLists(policy) {
		return errors.New("architecture policy contradicts the compiled constitution")
	}
	return nil
}

func validArchitectureIdentity(policy architecturePolicy) bool {
	return policy.Schema == architectureSchema &&
		policy.CurrentSlice == architectureCurrentSlice &&
		policy.BaseCommit == architectureBaseCommit &&
		policy.ModulePath == architectureModule &&
		policy.InventoryFormat == architectureInventory
}

func validArchitectureLists(policy architecturePolicy) bool {
	return equalStrings(policy.RootDirectories, expectedRootDirectories()) &&
		equalStrings(policy.RootFiles, expectedRootFiles()) &&
		equalStrings(policy.Prohibited, expectedProhibitedSegments()) &&
		equalStrings(policy.Packages, expectedPackages()) &&
		equalStrings(policy.RustPackages, expectedRustPackages()) &&
		equalStrings(policy.Scripts, expectedScripts()) &&
		len(policy.Commands) == 0 && len(policy.FileExceptions) == 0 &&
		equalStrings(policy.ProhibitedPaths, expectedProhibitedPaths()) &&
		equalStrings(policy.ImportRules, expectedImportRules())
}
