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
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	validNosec = regexp.MustCompile(
		`^[[:space:]]+G[0-9]+(,G[0-9]+)*[[:space:]]+--[[:space:]]+[^[:space:]].*$`,
	)
	validNolint = regexp.MustCompile(
		`^:([a-z0-9][a-z0-9,-]*)[[:space:]]+--[[:space:]]+[^[:space:]].*$`,
	)
	shellcheckDirective = regexp.MustCompile(
		`#[[:space:]]*shellcheck[[:space:]]+disable`,
	)
	gosecDirective = regexp.MustCompile(
		`gosec:`,
	)
	staticcheckDirective = regexp.MustCompile(
		`^//lint:(ignore|file-ignore)([[:space:]]|$)`,
	)
	validShellcheck = regexp.MustCompile(
		`^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]+disable[[:space:]]*=[[:space:]]*SC[0-9]+(,SC[0-9]+)*[[:space:]]+#[[:space:]]+[^[:space:]].*$`,
	)
)

func goSuppressionFindings(path string, source []byte) []string {
	var findings []string
	for _, comment := range goCommentLines(source) {
		text := comment.text
		if gosecDirective.MatchString(text) {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: invalid gosec suppression", path, comment.line,
			))
		}
		if comment.lineComment &&
			staticcheckDirective.MatchString(strings.TrimSpace(text)) {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: Staticcheck suppressions are prohibited", path, comment.line,
			))
		}
		_, nosec, hasNosec := strings.Cut(text, nosecMarker)
		if hasNosec && !validNosec.MatchString(nosec) {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: invalid gosec suppression", path, comment.line,
			))
		}
		_, nolint, hasNolint := strings.Cut(text, nolintMarker)
		if hasNolint {
			match := validNolint.FindStringSubmatch(nolint)
			if len(match) != 2 || contains(
				strings.Split(match[1], ","), "all",
			) {
				findings = append(findings, fmt.Sprintf(
					"%s:%d: invalid golangci-lint suppression",
					path,
					comment.line,
				))
			}
		}
	}
	return findings
}

type goCommentLine struct {
	line        int
	text        string
	lineComment bool
}

func goCommentLines(source []byte) []goCommentLine {
	files := token.NewFileSet()
	file := files.AddFile("source.go", -1, len(source))
	var lexer scanner.Scanner
	lexer.Init(file, source, nil, scanner.ScanComments)
	var comments []goCommentLine
	for {
		position, kind, literal := lexer.Scan()
		if kind == token.EOF {
			return comments
		}
		if kind != token.COMMENT {
			continue
		}
		start := files.PositionFor(position, false).Line
		lineComment := strings.HasPrefix(literal, "//")
		for offset, text := range strings.Split(literal, "\n") {
			comments = append(comments, goCommentLine{
				line:        start + offset,
				text:        strings.TrimSuffix(text, "\r"),
				lineComment: lineComment,
			})
		}
	}
}

func shellSuppressionFindings(path string, source []byte) []string {
	file, err := syntax.NewParser(syntax.KeepComments(true)).Parse(
		bytes.NewReader(source),
		path,
	)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse shell source: %v", path, err)}
	}
	var findings []string
	syntax.Walk(file, func(node syntax.Node) bool {
		comment, ok := node.(*syntax.Comment)
		if !ok {
			return true
		}
		line := []byte("#" + comment.Text)
		if !shellcheckDirective.Match(line) || validShellcheck.Match(line) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s:%d: invalid ShellCheck suppression",
			path,
			comment.Pos().Line(),
		))
		return true
	})
	return findings
}
