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
	"strings"

	"go.yaml.in/yaml/v3"
)

func printActions(output io.Writer, path string, root *yaml.Node) error {
	if err := printJobActions(output, path, mappingValue(root, "jobs")); err != nil {
		return err
	}
	if runs := mappingValue(root, "runs"); runs != nil {
		runs = resolveAlias(runs)
		if runs.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: runs must be a mapping", path, runs.Line)
		}
		if err := printStepActions(output, path, mappingValue(runs, "steps")); err != nil {
			return err
		}
		image := resolveAlias(mappingValue(runs, "image"))
		if image != nil {
			if image.Kind != yaml.ScalarNode {
				return fmt.Errorf("%s:%d: action image must be scalar", path, image.Line)
			}
			if strings.HasPrefix(image.Value, "docker://") {
				return printUses(output, path, image, runs.LineComment)
			}
		}
	}
	return nil
}

func printJobActions(output io.Writer, path string, jobs *yaml.Node) error {
	jobs = resolveAlias(jobs)
	if jobs == nil {
		return nil
	}
	if jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("%s:%d: jobs must be a mapping", path, jobs.Line)
	}
	for index := 0; index < len(jobs.Content); index += 2 {
		job := resolveAlias(jobs.Content[index+1])
		if job.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: job must be a mapping", path, job.Line)
		}
		if err := printUses(
			output,
			path,
			mappingValue(job, "uses"),
			job.LineComment,
		); err != nil {
			return err
		}
		if err := printJobImages(output, path, job); err != nil {
			return err
		}
		if err := printStepActions(output, path, mappingValue(job, "steps")); err != nil {
			return err
		}
	}
	return nil
}

func printJobImages(output io.Writer, path string, job *yaml.Node) error {
	container := resolveAlias(mappingValue(job, "container"))
	if container != nil {
		if container.Kind == yaml.MappingNode {
			container = mappingValue(container, "image")
		}
		if err := printDockerImage(output, path, container); err != nil {
			return err
		}
	}
	services := resolveAlias(mappingValue(job, "services"))
	if services == nil {
		return nil
	}
	if services.Kind != yaml.MappingNode {
		return fmt.Errorf("%s:%d: services must be a mapping", path, services.Line)
	}
	for index := 0; index < len(services.Content); index += 2 {
		service := resolveAlias(services.Content[index+1])
		if service == nil || service.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: service must be a mapping", path, services.Line)
		}
		if err := printDockerImage(
			output,
			path,
			mappingValue(service, "image"),
		); err != nil {
			return err
		}
	}
	return nil
}

func printDockerImage(output io.Writer, path string, image *yaml.Node) error {
	image = resolveAlias(image)
	if image == nil {
		return errors.New("container image is missing")
	}
	if image.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s:%d: container image must be scalar", path, image.Line)
	}
	value := image.Value
	if !strings.HasPrefix(value, "docker://") {
		value = "docker://" + value
	}
	return printReference(output, path, image.Line, value, image.LineComment, "")
}

func printStepActions(output io.Writer, path string, steps *yaml.Node) error {
	steps = resolveAlias(steps)
	if steps == nil {
		return nil
	}
	if steps.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s:%d: steps must be a sequence", path, steps.Line)
	}
	for _, step := range steps.Content {
		step = resolveAlias(step)
		if step.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: step must be a mapping", path, step.Line)
		}
		if err := printUses(
			output,
			path,
			mappingValue(step, "uses"),
			step.LineComment,
		); err != nil {
			return err
		}
	}
	return nil
}

func printUses(
	output io.Writer,
	path string,
	uses *yaml.Node,
	containerComment string,
) error {
	uses = resolveAlias(uses)
	if uses == nil {
		return nil
	}
	if uses.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s:%d: action reference must be scalar", path, uses.Line)
	}
	value := strings.TrimSpace(uses.Value)
	return printReference(
		output,
		path,
		uses.Line,
		value,
		uses.LineComment,
		containerComment,
	)
}

func printReference(
	output io.Writer,
	path string,
	line int,
	value string,
	comment string,
	containerComment string,
) error {
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s:%d: action reference contains a control character", path, line)
	}
	if comment == "" {
		comment = containerComment
	}
	if _, err := fmt.Fprintf(output, "%s:%d:%s", path, line, value); err != nil {
		return fmt.Errorf("write action reference: %w", err)
	}
	if comment != "" {
		if _, err := fmt.Fprintf(output, " %s", comment); err != nil {
			return fmt.Errorf("write action annotation: %w", err)
		}
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return fmt.Errorf("finish action reference: %w", err)
	}
	return nil
}
