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

func rustIncludeLine(tokens []rustPolicyToken) (int, bool) {
	inUse := false
	var macroDepth []bool
	for index, token := range tokens {
		if next, delimiter := rustMacroDelimiter(tokens, index, macroDepth); delimiter {
			macroDepth = next
			continue
		}
		switch token.text {
		case "use":
			inUse = true
		case ";":
			inUse = false
		case "include":
			if rustIncludeToken(tokens, index, inUse, macroDepth) {
				return token.line, true
			}
		}
	}
	return 0, false
}

func rustIncludeToken(
	tokens []rustPolicyToken,
	index int,
	inUse bool,
	macroDepth []bool,
) bool {
	alias := index > 0 && tokens[index-1].text == "as"
	direct := index+1 < len(tokens) && tokens[index+1].text == "!"
	forwarded := len(macroDepth) > 0 && macroDepth[len(macroDepth)-1]
	return inUse && !alias || direct || forwarded
}

func rustMacroIgnoreLine(tokens []rustPolicyToken) (int, bool) {
	var macroDepth []bool
	for index, token := range tokens {
		if next, delimiter := rustMacroDelimiter(tokens, index, macroDepth); delimiter {
			macroDepth = next
			continue
		}
		if rustForwardedIgnore(tokens, index, macroDepth) {
			return token.line, true
		}
	}
	return 0, false
}

func rustMacroDelimiter(
	tokens []rustPolicyToken,
	index int,
	depth []bool,
) ([]bool, bool) {
	switch tokens[index].text {
	case "(", "[", "{":
		inMacro := index > 0 && tokens[index-1].text == "!"
		if len(depth) > 0 && depth[len(depth)-1] {
			inMacro = true
		}
		return append(depth, inMacro), true
	case ")", "]", "}":
		if len(depth) > 0 {
			depth = depth[:len(depth)-1]
		}
		return depth, true
	default:
		return depth, false
	}
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
