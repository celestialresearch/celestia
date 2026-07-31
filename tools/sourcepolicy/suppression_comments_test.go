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
	"slices"
	"strings"
	"testing"
)

func TestGoSuppressionsIgnoreStringLiterals(t *testing.T) {
	source := []byte(strings.Join([]string{
		"package fixture",
		`const nosec = "// #no` + `sec"`,
		"const nolint = `//no" + "lint:all`",
		`const gosec = "gosec:disable"`,
	}, "\n"))
	if findings := goSuppressionFindings("source.go", source); len(findings) != 0 {
		t.Fatalf("findings = %v", findings)
	}
}

func TestGoSuppressionsReportCommentLines(t *testing.T) {
	source := []byte(strings.Join([]string{
		"package fixture",
		"const ordinary = 1 // #no" + "sec",
		"/* explanatory line",
		"//no" + "lint:all",
		"gosec:disable",
		"*" + "/",
	}, "\n"))
	want := []string{
		"source.go:2: invalid gosec suppression",
		"source.go:4: invalid golangci-lint suppression",
		"source.go:5: invalid gosec suppression",
	}
	if findings := goSuppressionFindings("source.go", source); !slices.Equal(findings, want) {
		t.Fatalf("findings = %v, want %v", findings, want)
	}
}

func TestGoSuppressionsUsePhysicalLines(t *testing.T) {
	source := []byte(strings.Join([]string{
		"package fixture",
		"//line generated.go:100",
		"//no" + "lint:all",
	}, "\n"))
	want := []string{
		"source.go:3: invalid golangci-lint suppression",
	}
	if findings := goSuppressionFindings("source.go", source); !slices.Equal(findings, want) {
		t.Fatalf("findings = %v, want %v", findings, want)
	}
}

func TestGoSuppressionsAcceptExplainedComments(t *testing.T) {
	source := []byte(strings.Join([]string{
		"package fixture",
		"const ordinary = 1 // #no" + "sec G304 -- bounded repository source",
		"//no" + "lint:errcheck -- checked by the owner",
	}, "\n"))
	if findings := goSuppressionFindings("source.go", source); len(findings) != 0 {
		t.Fatalf("findings = %v", findings)
	}
}
