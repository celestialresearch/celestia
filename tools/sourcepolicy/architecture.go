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
)

func runArchitecturePolicy(
	stderr io.Writer,
	inventory func() ([]string, error),
	executableInventory func([]string) ([]string, error),
	readFile func(string) ([]byte, error),
) int {
	// Readers are not cancellable. Returning early would detach repository work.
	findings, err := evaluateArchitecture(inventory, executableInventory, readFile)
	return architectureEvaluationStatus(stderr, findings, err)
}

func architectureEvaluationStatus(
	stderr io.Writer, findings []string, err error,
) int {
	if err != nil {
		writeArchitectureError(stderr, err)
		return 1
	}
	if len(findings) == 0 {
		return 0
	}
	writeArchitectureError(
		stderr, errors.New(strings.Join(findings, "\n")),
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
