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

//go:build actionpolicy

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	actionsMode     = "actions"
	permissionsMode = "permissions"
)

type document struct {
	path string
	data []byte
}

func main() {
	if len(os.Args) != 2 ||
		(os.Args[1] != actionsMode && os.Args[1] != permissionsMode) {
		fmt.Fprintln(os.Stderr, "Usage: actionpolicy actions|permissions")
		os.Exit(2)
	}

	documents, err := readDocuments()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	failed := false
	for _, document := range documents {
		if err := inspect(document, os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func readDocuments() ([]document, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read action documents: %w", err)
	}
	data = bytes.TrimSuffix(data, []byte{0})
	if len(data) == 0 {
		return nil, nil
	}

	raw := bytes.Split(data, []byte{0})
	if len(raw)%2 != 0 {
		return nil, errors.New("action document stream is incomplete")
	}
	documents := make([]document, len(raw)/2)
	for index := 0; index < len(raw); index += 2 {
		if len(raw[index]) == 0 {
			return nil, errors.New("action document contains an empty path")
		}
		documents[index/2] = document{
			path: string(raw[index]),
			data: raw[index+1],
		}
	}
	return documents, nil
}

func inspect(document document, mode string) error {
	var rootDocument yaml.Node
	if err := yaml.Unmarshal(document.data, &rootDocument); err != nil {
		return fmt.Errorf("%s: parse workflow: %w", document.path, err)
	}
	if len(rootDocument.Content) != 1 ||
		rootDocument.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: workflow root must be a mapping", document.path)
	}

	root := rootDocument.Content[0]
	if mode == actionsMode {
		return printActions(document.path, root)
	}
	return checkPermissions(document.path, root)
}

func printActions(path string, root *yaml.Node) error {
	if jobs := mappingValue(root, "jobs"); jobs != nil {
		jobs = resolveAlias(jobs)
		if jobs.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: jobs must be a mapping", path, jobs.Line)
		}
		for index := 0; index < len(jobs.Content); index += 2 {
			job := resolveAlias(jobs.Content[index+1])
			if job.Kind != yaml.MappingNode {
				continue
			}
			printUses(path, mappingValue(job, "uses"), job.LineComment)
			printStepActions(path, mappingValue(job, "steps"))
		}
	}
	if runs := mappingValue(root, "runs"); runs != nil {
		runs = resolveAlias(runs)
		if runs.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: runs must be a mapping", path, runs.Line)
		}
		printStepActions(path, mappingValue(runs, "steps"))
	}
	return nil
}

func printStepActions(path string, steps *yaml.Node) {
	steps = resolveAlias(steps)
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return
	}
	for _, step := range steps.Content {
		step = resolveAlias(step)
		if step.Kind == yaml.MappingNode {
			printUses(path, mappingValue(step, "uses"), step.LineComment)
		}
	}
}

func printUses(path string, uses *yaml.Node, containerComment string) {
	if uses == nil || uses.Kind != yaml.ScalarNode {
		return
	}
	value := strings.TrimSpace(uses.Value)
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") {
		return
	}
	fmt.Printf("%s:%d:%s", path, uses.Line, value)
	comment := uses.LineComment
	if comment == "" {
		comment = containerComment
	}
	if comment != "" {
		fmt.Printf(" %s", comment)
	}
	fmt.Println()
}

func checkPermissions(path string, root *yaml.Node) error {
	if grantsSecurityWrite(mappingValue(root, "permissions")) {
		return fmt.Errorf("%s: security-events write must be job-scoped", path)
	}

	jobs := mappingValue(root, "jobs")
	if jobs == nil {
		return nil
	}
	jobs = resolveAlias(jobs)
	if jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("%s:%d: jobs must be a mapping", path, jobs.Line)
	}

	var failures []string
	for index := 0; index < len(jobs.Content); index += 2 {
		name := jobs.Content[index].Value
		job := resolveAlias(jobs.Content[index+1])
		if job.Kind != yaml.MappingNode ||
			!grantsSecurityWrite(mappingValue(job, "permissions")) {
			continue
		}
		if !hasCodeQLAnalysis(mappingValue(job, "steps")) {
			failures = append(
				failures,
				fmt.Sprintf("%s: %s has security-events write without CodeQL analysis", path, name),
			)
		}
	}
	return errors.Join(stringsToErrors(failures)...)
}

func grantsSecurityWrite(permissions *yaml.Node) bool {
	permissions = resolveAlias(permissions)
	if permissions == nil {
		return false
	}
	if permissions.Kind == yaml.ScalarNode {
		return permissions.Value == "write-all"
	}
	if permissions.Kind != yaml.MappingNode {
		return false
	}
	value := mappingValue(permissions, "security-events")
	return value != nil && value.Kind == yaml.ScalarNode && value.Value == "write"
}

func hasCodeQLAnalysis(steps *yaml.Node) bool {
	steps = resolveAlias(steps)
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return false
	}
	for _, step := range steps.Content {
		step = resolveAlias(step)
		if step.Kind != yaml.MappingNode {
			continue
		}
		uses := mappingValue(step, "uses")
		if uses != nil && uses.Kind == yaml.ScalarNode &&
			strings.HasPrefix(uses.Value, "github/codeql-action/analyze@") {
			return true
		}
	}
	return false
}

func mappingValue(mapping *yaml.Node, name string) *yaml.Node {
	mapping = resolveAlias(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == name {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

func stringsToErrors(values []string) []error {
	errs := make([]error, len(values))
	for index, value := range values {
		errs[index] = errors.New(value)
	}
	return errs
}
