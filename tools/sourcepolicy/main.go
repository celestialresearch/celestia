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
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	modeSuppressions = "suppressions"
	modeTestSkips    = "test-skips"
)

func main() {
	if len(os.Args) != 2 ||
		(os.Args[1] != modeSuppressions && os.Args[1] != modeTestSkips) {
		fmt.Fprintln(os.Stderr, "usage: sourcepolicy [suppressions|test-skips]")
		os.Exit(2)
	}
	files, err := sourceFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var findings []string
	for _, path := range files {
		switch filepath.Ext(path) {
		case ".go":
			if os.Args[1] == modeTestSkips {
				findings = append(findings, goSkipFindings(path)...)
			}
		case ".rs":
			// #nosec G304 -- Git supplies paths from the repository inventory.
			source, readErr := os.ReadFile(path)
			if readErr != nil {
				findings = append(findings, fmt.Sprintf("%s: %v", path, readErr))
				continue
			}
			findings = append(findings, rustFindings(path, source, os.Args[1])...)
		}
	}
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, strings.Join(findings, "\n"))
	os.Exit(1)
}

func sourceFiles() ([]string, error) {
	git := os.Getenv("CELESTIA_GIT_BIN")
	if git == "" {
		git = "git"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204,G702 -- The testable Git command is an explicit repository control.
	command := exec.CommandContext(
		ctx, git, "ls-files", "-co", "--exclude-standard", "-z",
	)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("inventory source files: %w", err)
	}
	parts := bytes.Split(output, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			files = append(files, string(part))
		}
	}
	return files, nil
}

func goSkipFindings(path string) []string {
	if !strings.HasSuffix(path, "_test.go") {
		return nil
	}
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, 0)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Go test: %v", path, err)}
	}
	var findings []string
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || !isSkipMethod(selector.Sel.Name) {
			return true
		}
		position := files.Position(selector.Pos())
		findings = append(findings,
			fmt.Sprintf("%s:%d: Go tests must not skip cases", path, position.Line))
		return true
	})
	return findings
}

func isSkipMethod(name string) bool {
	return name == "Skip" || name == "Skipf" || name == "SkipNow"
}

type rustAttribute struct {
	line int
	text string
}

func rustFindings(path string, source []byte, mode string) []string {
	attributes, err := rustAttributes(source)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Rust attributes: %v", path, err)}
	}
	var findings []string
	for _, attribute := range attributes {
		words := identifiers(attribute.text)
		switch mode {
		case modeTestSkips:
			if contains(words, "ignore") {
				findings = append(findings, fmt.Sprintf(
					"%s:%d: Rust tests must not ignore cases", path, attribute.line))
			}
		case modeSuppressions:
			if contains(words, "allow") || contains(words, "expect") {
				if !validClippySuppression(attribute.text) {
					findings = append(findings, fmt.Sprintf(
						"%s:%d: invalid Clippy suppression", path, attribute.line))
				}
			}
		}
	}
	return findings
}

func rustAttributes(source []byte) ([]rustAttribute, error) {
	var attributes []rustAttribute
	for index, line := 0, 1; index < len(source); {
		next, nextLine, ok := skipRustTrivia(source, index, line)
		index, line = next, nextLine
		if !ok {
			return nil, errors.New("unterminated comment")
		}
		if index >= len(source) {
			break
		}
		if source[index] != '#' {
			index, line = skipRustToken(source, index, line)
			continue
		}
		attribute, nextIndex, nextLine, found, attributeErr :=
			readRustAttribute(source, index, line)
		if attributeErr != nil {
			return nil, attributeErr
		}
		if !found {
			index++
			continue
		}
		attributes = append(attributes, attribute)
		index, line = nextIndex, nextLine
	}
	return attributes, nil
}

func readRustAttribute(
	source []byte,
	index, line int,
) (rustAttribute, int, int, bool, error) {
	start, startLine := index, line
	index++
	if index < len(source) && source[index] == '!' {
		index++
	}
	if index >= len(source) || source[index] != '[' {
		return rustAttribute{}, index, line, false, nil
	}
	depth := 1
	for index++; index < len(source) && depth > 0; {
		nextIndex, nextLine, nextDepth, err :=
			advanceRustAttribute(source, index, line, depth)
		if err != nil {
			return rustAttribute{}, index, line, false, err
		}
		index, line, depth = nextIndex, nextLine, nextDepth
	}
	if depth != 0 {
		return rustAttribute{}, index, line, false,
			errors.New("unterminated attribute")
	}
	return rustAttribute{
		line: startLine,
		text: string(source[start:index]),
	}, index, line, true, nil
}

func advanceRustAttribute(
	source []byte,
	index, line, depth int,
) (int, int, int, error) {
	if source[index] == '\n' {
		return index + 1, line + 1, depth, nil
	}
	if source[index] == '"' || source[index] == '\'' {
		index, line = skipRustToken(source, index, line)
		return index, line, depth, nil
	}
	if index+1 < len(source) && source[index] == '/' &&
		(source[index+1] == '/' || source[index+1] == '*') {
		var valid bool
		index, line, valid = skipRustTrivia(source, index, line)
		if !valid {
			return index, line, depth, errors.New("unterminated comment")
		}
		return index, line, depth, nil
	}
	switch source[index] {
	case '[':
		depth++
	case ']':
		depth--
	}
	return index + 1, line, depth, nil
}

func skipRustTrivia(source []byte, index, line int) (int, int, bool) {
	for index < len(source) {
		if unicode.IsSpace(rune(source[index])) {
			index, line = skipRustWhitespace(source, index, line)
			continue
		}
		if index+1 >= len(source) || source[index] != '/' {
			return index, line, true
		}
		if source[index+1] == '/' {
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
			continue
		}
		if source[index+1] == '*' {
			index, line, valid := skipRustBlockComment(source, index, line)
			if !valid {
				return index, line, false
			}
			continue
		}
		return index, line, true
	}
	return index, line, true
}

func skipRustWhitespace(source []byte, index, line int) (int, int) {
	for index < len(source) && unicode.IsSpace(rune(source[index])) {
		if source[index] == '\n' {
			line++
		}
		index++
	}
	return index, line
}

func skipRustBlockComment(source []byte, index, line int) (int, int, bool) {
	index += 2
	depth := 1
	for index < len(source) && depth > 0 {
		if source[index] == '\n' {
			line++
		}
		if index+1 < len(source) && source[index] == '/' &&
			source[index+1] == '*' {
			depth++
			index += 2
		} else if index+1 < len(source) && source[index] == '*' &&
			source[index+1] == '/' {
			depth--
			index += 2
		} else {
			index++
		}
	}
	return index, line, depth == 0
}

func skipRustToken(source []byte, index, line int) (int, int) {
	if source[index] != '"' && source[index] != '\'' {
		return index + 1, line
	}
	quote := source[index]
	index++
	escaped := false
	for index < len(source) {
		current := source[index]
		index++
		if current == '\n' {
			line++
		}
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
		} else if current == quote {
			break
		}
	}
	return index, line
}

func identifiers(value string) []string {
	return strings.FieldsFunc(value, func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character) &&
			character != '_'
	})
}

func contains(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}

func validClippySuppression(value string) bool {
	compact := strings.Join(strings.Fields(value), "")
	var body string
	switch {
	case strings.HasPrefix(compact, "#[allow(clippy::"):
		body = strings.TrimPrefix(compact, "#[allow(clippy::")
	case strings.HasPrefix(compact, "#[expect(clippy::"):
		body = strings.TrimPrefix(compact, "#[expect(clippy::")
	default:
		return false
	}
	rule, reason, ok := strings.Cut(body, `,reason="`)
	if !ok || rule == "" || rule == "all" || !validRustIdentifier(rule) {
		return false
	}
	return reason != `")]` && strings.HasSuffix(reason, `")]`)
}

func validRustIdentifier(value string) bool {
	for _, character := range value {
		if !unicode.IsLower(character) && !unicode.IsDigit(character) &&
			character != '_' {
			return false
		}
	}
	return true
}
