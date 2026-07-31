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
	"strings"
)

type rustAttribute struct {
	line int
	text string
}

func rustFindings(path string, source []byte, mode string) []string {
	if finding := rustExpansionFinding(path, source, mode); finding != "" {
		return []string{finding}
	}
	attributes, err := rustAttributes(source)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Rust attributes: %v", path, err)}
	}
	var findings []string
	for _, attribute := range attributes {
		findings = append(
			findings,
			rustAttributeFindings(path, attribute, mode)...,
		)
	}
	return findings
}

func rustExpansionFinding(path string, source []byte, mode string) string {
	if line, found := rustDocExitLine(source); mode == modeTestSkips && found {
		return fmt.Sprintf(
			"%s:%d: Rust documentation tests must not exit", path, line,
		)
	}
	tokens, valid := rustPolicyTokens(source)
	if !valid {
		return fmt.Sprintf("%s: parse Rust source: unterminated token", path)
	}
	if line, found := rustIncludeLine(tokens); found {
		return fmt.Sprintf("%s:%d: Rust include! is prohibited", path, line)
	}
	if line, found := rustMacroIgnoreLine(tokens); mode == modeTestSkips && found {
		return fmt.Sprintf(
			"%s:%d: Rust tests must not ignore cases", path, line,
		)
	}
	return ""
}

func rustDocExitLine(source []byte) (int, bool) {
	blockDepth := 0
	var documentation strings.Builder
	for line := range strings.SplitSeq(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		doc := ""
		switch {
		case blockDepth > 0:
			doc = rustBlockDocumentation(trimmed, &blockDepth)
		case strings.HasPrefix(trimmed, "///"),
			strings.HasPrefix(trimmed, "//!"):
			doc = trimmed[3:]
		case strings.HasPrefix(trimmed, "/**"),
			strings.HasPrefix(trimmed, "/*!"):
			blockDepth = 1
			doc = rustBlockDocumentation(trimmed[3:], &blockDepth)
		}
		documentation.WriteString(doc)
		documentation.WriteByte('\n')
	}
	tokens, valid := rustPolicyTokens([]byte(documentation.String()))
	if !valid {
		return 0, false
	}
	for index, token := range tokens {
		if token.text == "exit" && rustExitIsExecutable(tokens, index) {
			return token.line, true
		}
	}
	return 0, false
}

func rustExitIsExecutable(tokens []rustPolicyToken, index int) bool {
	if index+1 < len(tokens) && tokens[index+1].text == "(" {
		return true
	}
	if index+2 < len(tokens) &&
		tokens[index+1].text == ")" && tokens[index+2].text == "(" {
		return true
	}
	if index > 1 &&
		tokens[index-2].text == ":" && tokens[index-1].text == ":" {
		return true
	}
	for preceding := index - 1; preceding >= 0; preceding-- {
		if tokens[preceding].text == ";" {
			break
		}
		if tokens[preceding].text == "use" {
			return true
		}
	}
	return false
}

func rustBlockDocumentation(line string, depth *int) string {
	var documentation strings.Builder
	for index := 0; index < len(line) && *depth > 0; {
		switch {
		case strings.HasPrefix(line[index:], "/*"):
			*depth++
			index += 2
		case strings.HasPrefix(line[index:], "*/"):
			*depth--
			index += 2
		default:
			if *depth == 1 {
				documentation.WriteByte(line[index])
			}
			index++
		}
	}
	return documentation.String()
}

func rustIncludeLine(tokens []rustPolicyToken) (int, bool) {
	inUse := false
	for index, token := range tokens {
		switch token.text {
		case "use":
			inUse = true
		case ";":
			inUse = false
		case "include":
			alias := index > 0 && tokens[index-1].text == "as"
			if (inUse && !alias) ||
				index+1 < len(tokens) && tokens[index+1].text == "!" {
				return token.line, true
			}
		}
	}
	return 0, false
}

func rustMacroIgnoreLine(tokens []rustPolicyToken) (int, bool) {
	var macroDepth []bool
	for index, token := range tokens {
		switch token.text {
		case "(", "[", "{":
			inMacro := index > 0 && tokens[index-1].text == "!"
			if len(macroDepth) > 0 && macroDepth[len(macroDepth)-1] {
				inMacro = true
			}
			macroDepth = append(macroDepth, inMacro)
		case ")", "]", "}":
			if len(macroDepth) > 0 {
				macroDepth = macroDepth[:len(macroDepth)-1]
			}
		default:
			if rustForwardedIgnore(tokens, index, macroDepth) {
				return token.line, true
			}
		}
	}
	return 0, false
}

func rustForwardedIgnore(
	tokens []rustPolicyToken,
	index int,
	macroDepth []bool,
) bool {
	return tokens[index].text == "ignore" &&
		(index+1 >= len(tokens) || tokens[index+1].text != "(") &&
		len(macroDepth) > 0 && macroDepth[len(macroDepth)-1]
}

func rustAttributeFindings(
	path string,
	attribute rustAttribute,
	mode string,
) []string {
	words := rustAttributeIdentifiers([]byte(attribute.text))
	if rustAttributeSetsPath([]byte(attribute.text)) {
		return []string{fmt.Sprintf(
			"%s:%d: Rust path attributes are prohibited", path, attribute.line,
		)}
	}
	switch mode {
	case modeTestSkips:
		if contains(words, "doc") {
			return []string{fmt.Sprintf(
				"%s:%d: Rust doc attributes are prohibited",
				path,
				attribute.line,
			)}
		}
		if contains(words, "ignore") {
			return []string{fmt.Sprintf(
				"%s:%d: Rust tests must not ignore cases", path, attribute.line,
			)}
		}
	case modeSuppressions:
		if strings.Contains(attribute.text, "$") {
			return []string{fmt.Sprintf(
				"%s:%d: dynamic Rust attributes are prohibited",
				path,
				attribute.line,
			)}
		}
		if (contains(words, "allow") || contains(words, "expect")) &&
			!validClippySuppression(attribute.text) {
			return []string{fmt.Sprintf(
				"%s:%d: invalid Clippy suppression", path, attribute.line,
			)}
		}
	}
	return nil
}
