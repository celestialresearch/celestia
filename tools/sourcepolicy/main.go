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
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	modeAll          = "all"
	modeSuppressions = "suppressions"
	modeTestSkips    = "test-skips"
	modeManifest     = "manifest"
	modeArchitecture = "architecture"
	modeSourceFiles  = "source-files"
)

type quotedDiagnosticError struct {
	cause error
}

func (err quotedDiagnosticError) Error() string {
	return strconv.QuoteToASCII(err.cause.Error())
}

func (err quotedDiagnosticError) Unwrap() error {
	return err.cause
}

func quotedDiagnostic(err error) error {
	return quotedDiagnosticError{cause: err}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == modeAll {
		os.Exit(runAll(os.Stdout, os.Stderr))
	}
	if len(os.Args) == 2 && os.Args[1] == modeArchitecture {
		os.Exit(runArchitecturePolicy(
			os.Stderr, sourceFiles, sourceExecutables, readSource,
		))
	}
	if len(os.Args) == 2 && os.Args[1] == modeManifest {
		os.Exit(runManifestPolicy(os.Stderr, readSource))
	}
	if len(os.Args) == 2 && os.Args[1] == modeSourceFiles {
		os.Exit(runSourceFileMode(os.Stderr, sourceFiles, readSource))
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

func runAll(stdout, stderr io.Writer) int {
	files, err := sourceFiles()
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	inventory := func() ([]string, error) {
		return slices.Clone(files), nil
	}
	return runChecks(stdout, stderr, allPolicyChecks(files, inventory))
}

func allPolicyChecks(
	files []string,
	inventory func() ([]string, error),
) []policyCheck {
	return []policyCheck{
		{"Architecture", func(output io.Writer) int {
			return runArchitecturePolicy(
				output, inventory, sourceExecutables, readSource,
			)
		}},
		{"Manifests", func(output io.Writer) int {
			return runManifestPolicy(output, readSource)
		}},
		{"Test Skips", func(output io.Writer) int {
			return runFiles(files, modeTestSkips, output, readSource)
		}},
		{"Suppressions", func(output io.Writer) int {
			return runFiles(files, modeSuppressions, output, readSource)
		}},
		{"Source Files", func(output io.Writer) int {
			return runSourceFiles(files, output, readSource)
		}},
	}
}

type policyCheck struct {
	name string
	run  func(io.Writer) int
}

func runChecks(stdout, stderr io.Writer, checks []policyCheck) int {
	for _, check := range checks {
		if _, err := fmt.Fprintf(stdout, "        %-34s[RUN ]\n", check.name); err != nil {
			return 1
		}
		started := time.Now()
		status := check.run(stderr)
		if status == 0 {
			if _, err := fmt.Fprintf(
				stdout, "        %-34s[PASS] %s\n",
				check.name, roundedDuration(time.Since(started)),
			); err != nil {
				return 1
			}
			continue
		}
		if _, err := fmt.Fprintf(
			stdout, "        %-34s[FAIL] %s\n",
			check.name, roundedDuration(time.Since(started)),
		); err != nil {
			return 1
		}
		return status
	}
	return 0
}

func roundedDuration(duration time.Duration) time.Duration {
	return duration.Round(time.Millisecond)
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
			stderr, "usage: sourcepolicy [all|architecture|manifest|source-files|suppressions|test-skips]",
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
	return runFiles(files, args[0], stderr, readFile)
}

func runSourceFiles(
	files []string,
	stderr io.Writer,
	readFile func(string) ([]byte, error),
) int {
	findings := sourceFileFindings(files, readFile)
	if len(findings) == 0 {
		return 0
	}
	if _, err := fmt.Fprintln(stderr, strings.Join(findings, "\n")); err != nil {
		return 1
	}
	return 1
}

func runSourceFileMode(
	stderr io.Writer,
	inventory func() ([]string, error),
	readFile func(string) ([]byte, error),
) int {
	files, err := inventory()
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	return runSourceFiles(files, stderr, readFile)
}

func runFiles(
	files []string,
	mode string,
	stderr io.Writer,
	readFile func(string) ([]byte, error),
) int {
	findings, err := policyFindings(files, mode, readFile)
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
