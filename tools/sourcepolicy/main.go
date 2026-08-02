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
	"strings"
)

const (
	modeSuppressions = "suppressions"
	modeTestSkips    = "test-skips"
	modeManifest     = "manifest"
	modeArchitecture = "architecture"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == modeArchitecture {
		os.Exit(runArchitecturePolicy(
			os.Stderr, sourceFiles, sourceExecutables, readSource,
		))
	}
	if len(os.Args) == 2 && os.Args[1] == modeManifest {
		os.Exit(runManifestPolicy(os.Stderr, readSource))
	}
	if handled, status := runTestInventory(
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
	); handled {
		os.Exit(status)
	}
	os.Exit(run(os.Args[1:], os.Stderr, sourceFiles, readSource))
}

func run(
	args []string,
	stderr io.Writer,
	inventory func() ([]string, error),
	readFile func(string) ([]byte, error),
) int {
	if len(args) != 1 ||
		(args[0] != modeSuppressions && args[0] != modeTestSkips) {
		if _, err := fmt.Fprintln(
			stderr, "usage: sourcepolicy [architecture|manifest|suppressions|test-skips]",
		); err != nil {
			return 1
		}
		return 2
	}
	files, err := inventory()
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	findings, err := policyFindings(files, args[0], readFile)
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	if len(findings) == 0 {
		return 0
	}
	if _, err := fmt.Fprintln(stderr, strings.Join(findings, "\n")); err != nil {
		return 1
	}
	return 1
}
