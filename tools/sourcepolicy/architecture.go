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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

const (
	architecturePolicyPath   = "policies/architecture.json"
	architectureSchema       = "celestia.production.architecture.v1"
	architectureBaseCommit   = "ea8f840aa230f0498f82f3cd00dca22760cf6020"
	architectureModule       = "celestia.research/celestia"
	architectureCurrentSlice = "CEL-STRUCT-001"
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
	Commands        []string             `json:"declared_commands"`
	FileExceptions  []architectureExcept `json:"file_exceptions"`
	ImportRules     []string             `json:"forbidden_import_rules"`
	Legacy          []architectureLegacy `json:"legacy_packages"`
}

type architectureExcept struct {
	Path    string `json:"path"`
	Owner   string `json:"owner"`
	Reason  string `json:"reason"`
	Removal string `json:"removal_condition"`
	Expiry  string `json:"expires_at_completion"`
}

type architectureLegacy struct {
	Path          string `json:"path"`
	Count         int    `json:"inventory_count"`
	Digest        string `json:"inventory_sha256"`
	Destination   string `json:"destination"`
	Slice         string `json:"migration_slice"`
	Reason        string `json:"reason"`
	Expiry        string `json:"expires_at_completion"`
	AllowNewFiles bool   `json:"allow_new_files"`
}

type baseInventoryFunc func(string, string) ([]string, error)

func runArchitecturePolicy(
	stderr io.Writer,
	inventory func() ([]string, error),
	readFile func(string) ([]byte, error),
	baseInventory baseInventoryFunc,
) int {
	files, err := inventory()
	if err != nil {
		return writeArchitectureError(stderr, fmt.Errorf("inventory architecture: %w", err))
	}
	policyData, err := readFile(architecturePolicyPath)
	if err != nil {
		return writeArchitectureError(stderr, fmt.Errorf("read architecture policy: %w", err))
	}
	policy, err := decodeArchitecturePolicy(policyData)
	if err != nil {
		return writeArchitectureError(stderr, err)
	}
	findings, err := architectureFindings(files, policy, readFile, baseInventory)
	if err != nil {
		return writeArchitectureError(stderr, err)
	}
	if len(findings) == 0 {
		return 0
	}
	return writeArchitectureError(stderr, errors.New(strings.Join(findings, "\n")))
}

func writeArchitectureError(stderr io.Writer, err error) int {
	if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
		return 1
	}
	return 1
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
	return validateLegacyPolicy(policy.Legacy)
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
		len(policy.Commands) == 0 && len(policy.FileExceptions) == 0 &&
		equalStrings(policy.ImportRules, expectedImportRules())
}

func validateLegacyPolicy(legacy []architectureLegacy) error {
	expected := expectedLegacy()
	if len(legacy) != len(expected) {
		return errors.New("architecture policy must contain six legacy packages")
	}
	for index, entry := range legacy {
		want := expected[index]
		if entry.Path != want.Path || entry.Count != want.Count ||
			entry.Digest != want.Digest || entry.Destination != want.Destination ||
			entry.Slice != want.Slice || entry.Expiry != want.Expiry ||
			entry.AllowNewFiles || strings.TrimSpace(entry.Reason) == "" {
			return fmt.Errorf("invalid legacy package %q", entry.Path)
		}
	}
	return nil
}

func architectureFindings(
	files []string,
	policy architecturePolicy,
	readFile func(string) ([]byte, error),
	baseInventory baseInventoryFunc,
) ([]string, error) {
	if err := validateCurrentModule(readFile, policy.ModulePath); err != nil {
		return nil, err
	}
	findings := architecturePathFindings(files, policy)
	imports, err := architectureImportFindings(files, readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, imports...)
	legacyFindings, err := architectureLegacyFindings(files, policy, baseInventory)
	if err != nil {
		return nil, err
	}
	findings = append(findings, legacyFindings...)
	documentation, err := packageDocumentationFindings(files, policy, readFile)
	if err != nil {
		return nil, err
	}
	findings = append(findings, documentation...)
	sort.Strings(findings)
	return findings, nil
}

func validateCurrentModule(
	readFile func(string) ([]byte, error),
	expected string,
) error {
	data, err := readFile("go.mod")
	if err != nil {
		return fmt.Errorf("read module identity: %w", err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil || module.Module == nil || module.Module.Mod.Path != expected {
		return errors.New("go.mod: module identity contradicts architecture policy")
	}
	return nil
}

func architecturePathFindings(files []string, policy architecturePolicy) []string {
	roots := stringSet(policy.RootDirectories)
	rootFiles := stringSet(policy.RootFiles)
	packages := stringSet(policy.Packages)
	prohibited := stringSet(policy.Prohibited)
	var findings []string
	for _, file := range files {
		findings = append(findings, architectureFileFindings(
			file, roots, rootFiles, packages, stringSet(policy.Commands), prohibited,
		)...)
	}
	return findings
}

func architectureFileFindings(
	file string,
	roots, rootFiles, packages, commands, prohibited map[string]struct{},
) []string {
	if path.Clean(file) != file || !fs.ValidPath(file) {
		return []string{file + ": invalid tracked path"}
	}
	segments := strings.Split(file, "/")
	if len(segments) == 1 {
		if _, allowed := rootFiles[file]; !allowed {
			return []string{file + ": undeclared root file"}
		}
		return nil
	}
	if _, allowed := roots[segments[0]]; !allowed {
		return []string{file + ": unapproved root directory"}
	}
	findings := prohibitedPathFindings(file, segments, prohibited)
	return append(findings, architectureGoPathFindings(
		file, segments[0], packages, commands,
	)...)
}

func architectureGoPathFindings(
	file, root string, packages, commands map[string]struct{},
) []string {
	if !strings.HasSuffix(file, ".go") {
		return nil
	}
	directory := path.Dir(file)
	if root == "cmd" {
		if _, declared := commands[directory]; !declared {
			return []string{file + ": command is not declared"}
		}
		return nil
	}
	if root != "internal" && root != "tools" ||
		strings.Contains(directory, "/testdata/") || strings.HasSuffix(directory, "/testdata") {
		return nil
	}
	if _, declared := packages[directory]; !declared {
		return []string{file + ": Go package is not declared"}
	}
	return nil
}

func prohibitedPathFindings(
	file string, segments []string, prohibited map[string]struct{},
) []string {
	var findings []string
	for _, segment := range segments[1 : len(segments)-1] {
		if _, denied := prohibited[segment]; denied {
			findings = append(findings, file+": prohibited directory segment "+segment)
		}
	}
	if strings.EqualFold(segments[len(segments)-1], "private-key.pem") {
		findings = append(findings, file+": private-key path is prohibited")
	}
	return findings
}

func architectureLegacyFindings(
	files []string,
	policy architecturePolicy,
	baseInventory baseInventoryFunc,
) ([]string, error) {
	var findings []string
	for _, entry := range policy.Legacy {
		base, err := baseInventory(policy.BaseCommit, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("inventory legacy package %s: %w", entry.Path, err)
		}
		if len(base) != entry.Count || inventoryDigest(base) != entry.Digest {
			return nil, fmt.Errorf("legacy package %s does not match its base inventory", entry.Path)
		}
		allowed := stringSet(base)
		prefix := entry.Path + "/"
		for _, file := range files {
			if !strings.HasPrefix(file, prefix) {
				continue
			}
			if _, exists := allowed[file]; !exists {
				findings = append(findings, file+": legacy package inventory expanded")
			}
		}
	}
	return findings, nil
}

func packageDocumentationFindings(
	files []string,
	policy architecturePolicy,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	documented := make(map[string]bool, len(policy.Packages))
	for _, file := range files {
		if err := observePackageDocumentation(file, policy.Packages, documented, readFile); err != nil {
			return nil, err
		}
	}
	var findings []string
	for _, directory := range policy.Packages {
		if !documented[directory] {
			findings = append(findings, directory+": package documentation is missing")
		}
	}
	return findings, nil
}

func observePackageDocumentation(
	file string,
	packages []string,
	documented map[string]bool,
	readFile func(string) ([]byte, error),
) error {
	if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
		return nil
	}
	directory := path.Dir(file)
	if documented[directory] || !slices.Contains(packages, directory) {
		return nil
	}
	source, err := readFile(file)
	if err != nil {
		return fmt.Errorf("read package documentation %s: %w", file, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, source, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse package documentation %s: %w", file, err)
	}
	if parsed.Doc != nil && strings.HasPrefix(parsed.Doc.Text(), "Package "+parsed.Name.Name+" ") {
		documented[directory] = true
	}
	return nil
}

func gitBaseInventory(_ string, root string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "ls-tree", "-r", "-z", "--name-only", architectureBaseCommit)
	files, err := inventorySourceFiles(command, cancel)
	if err != nil {
		return nil, err
	}
	prefix := root + "/"
	return slices.DeleteFunc(files, func(file string) bool {
		return !strings.HasPrefix(file, prefix)
	}), nil
}

func inventoryDigest(files []string) string {
	values := slices.Clone(files)
	sort.Strings(values)
	digest := sha256.Sum256([]byte(strings.Join(values, "\n") + "\n"))
	return fmt.Sprintf("%x", digest)
}

func equalStrings(actual, expected []string) bool {
	return slices.Equal(actual, expected)
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
