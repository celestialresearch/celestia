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
	"strings"

	"go.yaml.in/yaml/v3"
)

func checkPermissions(path string, root *yaml.Node) error {
	workflowPermissions := mappingValue(root, "permissions")
	if workflowPermissions == nil {
		return fmt.Errorf("%s: workflow permissions: explicit permissions are required", path)
	}
	_, err := validatePermissions(workflowPermissions, false)
	if err != nil {
		return fmt.Errorf("%s: workflow permissions: %w", path, err)
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
		if job.Kind != yaml.MappingNode {
			continue
		}
		granted, err := validatePermissions(mappingValue(job, "permissions"), true)
		if err != nil {
			failures = append(
				failures,
				fmt.Sprintf("%s: %s permissions: %v", path, name, err),
			)
			continue
		}
		if !granted {
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

func validatePermissions(permissions *yaml.Node, allowSecurityWrite bool) (bool, error) {
	permissions = resolveAlias(permissions)
	if permissions == nil {
		return false, nil
	}
	if permissions.Kind == yaml.ScalarNode {
		if permissions.Value == "read-all" {
			return false, nil
		}
		if permissions.Value == "write-all" {
			return false, errors.New("write-all is prohibited")
		}
		return false, errors.New("permissions must be read-all or a mapping")
	}
	if permissions.Kind != yaml.MappingNode {
		return false, errors.New("permissions must be a mapping")
	}

	securityWrite := false
	for index := 0; index < len(permissions.Content); index += 2 {
		key := resolveAlias(permissions.Content[index])
		value := resolveAlias(permissions.Content[index+1])
		granted, err := validatePermissionValue(key.Value, value, allowSecurityWrite)
		if err != nil {
			return false, err
		}
		securityWrite = securityWrite || granted
	}
	return securityWrite, nil
}

func validatePermissionValue(
	name string,
	value *yaml.Node,
	allowSecurityWrite bool,
) (bool, error) {
	if value == nil || value.Kind != yaml.ScalarNode {
		return false, fmt.Errorf("%s permission must be scalar", name)
	}
	switch value.Value {
	case "read", "none":
		return false, nil
	case "write":
		if name == "security-events" && allowSecurityWrite {
			return true, nil
		}
		return false, fmt.Errorf("%s write permission is prohibited", name)
	default:
		return false, fmt.Errorf("%s permission is unsupported", name)
	}
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
		uses := resolveAlias(mappingValue(step, "uses"))
		if uses != nil && uses.Kind == yaml.ScalarNode &&
			strings.HasPrefix(uses.Value, "github/codeql-action/analyze@") {
			return true
		}
	}
	return false
}

func stringsToErrors(values []string) []error {
	errs := make([]error, len(values))
	for index, value := range values {
		errs[index] = errors.New(value)
	}
	return errs
}
