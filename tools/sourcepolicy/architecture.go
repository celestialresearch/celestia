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
	"time"
)

func runArchitecturePolicy(
	stderr io.Writer,
	inventory func() ([]string, error),
	executableInventory func([]string) ([]string, error),
	readFile func(string) ([]byte, error),
) int {
	return runArchitecturePolicyWithin(
		stderr, inventory, executableInventory, readFile,
		maxArchitectureDuration,
	)
}

type architectureEvaluation struct {
	findings []string
	err      error
}

func runArchitecturePolicyWithin(
	stderr io.Writer,
	inventory func() ([]string, error),
	executableInventory func([]string) ([]string, error),
	readFile func(string) ([]byte, error),
	duration time.Duration,
) int {
	result := make(chan architectureEvaluation, 1)
	go func() {
		findings, err := evaluateArchitecture(
			inventory, executableInventory, readFile,
		)
		result <- architectureEvaluation{findings: findings, err: err}
	}()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case evaluation := <-result:
		return architectureEvaluationStatus(stderr, evaluation)
	case <-timer.C:
		select {
		case evaluation := <-result:
			return architectureEvaluationStatus(stderr, evaluation)
		default:
		}
		writeArchitectureError(
			stderr, errors.New("architecture evaluation deadline exceeded"),
		)
		return 1
	}
}

func architectureEvaluationStatus(
	stderr io.Writer, evaluation architectureEvaluation,
) int {
	if evaluation.err != nil {
		writeArchitectureError(stderr, evaluation.err)
		return 1
	}
	if len(evaluation.findings) == 0 {
		return 0
	}
	writeArchitectureError(
		stderr, errors.New(strings.Join(evaluation.findings, "\n")),
	)
	return 1
}

func writeArchitectureError(stderr io.Writer, err error) {
	message := err.Error()
	if len(message)+1 > maxSourceBytes {
		message = "architecture diagnostic exceeded its output bound"
	}
	if _, writeErr := fmt.Fprintln(stderr, message); writeErr != nil {
		return
	}
}
