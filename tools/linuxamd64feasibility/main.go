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
	"io"
	"os"

	"celestia.research/celestia/internal/linuxamd64feasibility"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr, runBootstrapMain))
}

func runMain(arguments []string, stdout, stderr io.Writer, bootstrap func() int) int {
	if len(arguments) == 1 && arguments[0] == "--bootstrap" {
		return bootstrap()
	}
	return run(arguments, stdout, stderr)
}

func runBootstrap(gate, ready, fixture *os.File) int {
	return bootstrapStatus(linuxamd64feasibility.Bootstrap(gate, ready, fixture))
}

func bootstrapStatus(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) != 1 {
		if _, err := fmt.Fprintln(stderr, "usage: linuxamd64feasibility <evidence-root>"); err != nil {
			return 1
		}
		return 2
	}
	output := linuxamd64feasibility.Probe(arguments[0])
	if err := writeResult(stdout, output); err != nil {
		return 1
	}
	return 0
}

func writeResult(output io.Writer, data []byte) error {
	_, err := output.Write(data)
	return err
}
