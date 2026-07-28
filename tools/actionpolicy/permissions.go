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
	workflowWrite, err := securityWrite(mappingValue(root, "permissions"))
	if err != nil {
		return fmt.Errorf("%s: workflow permissions: %w", path, err)
	}
	if workflowWrite {
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
		if job.Kind != yaml.MappingNode {
			continue
		}
		granted, err := securityWrite(mappingValue(job, "permissions"))
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

func securityWrite(permissions *yaml.Node) (bool, error) {
	permissions = resolveAlias(permissions)
	if permissions == nil {
		return false, nil
	}
	if permissions.Kind == yaml.ScalarNode {
		if permissions.Value == "read-all" || permissions.Value == "{}" {
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
	value := resolveAlias(mappingValue(permissions, "security-events"))
	if value == nil {
		return false, nil
	}
	if value.Kind != yaml.ScalarNode {
		return false, errors.New("security-events permission must be scalar")
	}
	switch value.Value {
	case "write":
		return true, nil
	case "read", "none":
		return false, nil
	default:
		return false, errors.New("security-events permission is unsupported")
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
