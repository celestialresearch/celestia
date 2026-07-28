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
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

type document struct {
	path string
	data []byte
}

const (
	maxYAMLDepth      = 256
	maxYAMLNodeVisits = 1 << 20
)

type yamlValidator struct {
	active    map[*yaml.Node]bool
	remaining int
}

func inspect(document document, mode string, output io.Writer) error {
	var rootDocument yaml.Node
	if err := yaml.Unmarshal(document.data, &rootDocument); err != nil {
		return fmt.Errorf("%s: parse workflow: %w", document.path, err)
	}
	if len(rootDocument.Content) != 1 ||
		rootDocument.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: workflow root must be a mapping", document.path)
	}

	root := rootDocument.Content[0]
	validator := yamlValidator{
		active:    make(map[*yaml.Node]bool),
		remaining: maxYAMLNodeVisits,
	}
	if err := validator.validate(root, 0); err != nil {
		return fmt.Errorf("%s: invalid workflow structure: %w", document.path, err)
	}
	if mode == actionsMode {
		return printActions(output, document.path, root)
	}
	if isActionMetadata(document.path) {
		return nil
	}
	return checkPermissions(document.path, root)
}

func isActionMetadata(path string) bool {
	name := filepath.Base(path)
	if name != "action.yml" && name != "action.yaml" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	return !strings.HasPrefix(clean, ".github/workflows/") &&
		!strings.Contains(clean, "/.github/workflows/")
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

func validateDocumentPath(path []byte) error {
	if !utf8.Valid(path) {
		return errors.New("action document path is not valid UTF-8")
	}
	for _, value := range path {
		if value < 0x20 || value == 0x7f || value == ':' {
			return errors.New("action document path contains a reserved character")
		}
	}
	return nil
}

func (validator *yamlValidator) validate(node *yaml.Node, depth int) error {
	if err := validator.consume(depth); err != nil {
		return err
	}

	node = resolveAlias(node)
	if node == nil {
		return nil
	}
	if validator.active[node] {
		return errors.New("YAML aliases form a cycle")
	}
	validator.active[node] = true
	defer delete(validator.active, node)

	return validator.validateKind(node, depth)
}

func (validator *yamlValidator) consume(depth int) error {
	if depth > maxYAMLDepth {
		return errors.New("YAML nesting exceeds the depth limit")
	}
	if validator.remaining == 0 {
		return errors.New("YAML structure exceeds the traversal budget")
	}
	validator.remaining--
	return nil
}

func (validator *yamlValidator) validateKind(node *yaml.Node, depth int) error {
	switch node.Kind {
	case yaml.MappingNode:
		return validator.validateMapping(node, depth)
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validator.validate(child, depth+1); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		return nil
	case yaml.DocumentNode:
		return errors.New("nested YAML document is unsupported")
	case yaml.AliasNode:
		return errors.New("unresolved YAML alias")
	default:
		return errors.New("unsupported YAML node")
	}
	return nil
}

func (validator *yamlValidator) validateMapping(node *yaml.Node, depth int) error {
	if len(node.Content)%2 != 0 {
		return errors.New("YAML mapping is incomplete")
	}
	keys := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index]
		if key.Kind == yaml.AliasNode {
			return errors.New("YAML alias keys are unsupported")
		}
		if key == nil || key.Kind != yaml.ScalarNode {
			return errors.New("YAML mapping key is not scalar")
		}
		if key.Value == "<<" {
			return errors.New("YAML merge keys are unsupported")
		}
		if _, exists := keys[key.Value]; exists {
			return fmt.Errorf("duplicate YAML key %q", key.Value)
		}
		keys[key.Value] = struct{}{}
		if err := validator.validate(node.Content[index+1], depth+1); err != nil {
			return err
		}
	}
	return nil
}
