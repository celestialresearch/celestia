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
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

type rustPolicyToken struct {
	text string
	line int
}

func rustPolicyTokens(source []byte) ([]rustPolicyToken, bool) {
	var tokens []rustPolicyToken
	for index, line := 0, 1; index < len(source); {
		next, nextLine, valid := skipRustTrivia(source, index, line)
		index, line = next, nextLine
		if !valid || index >= len(source) {
			return tokens, valid
		}
		if rustTokenStart(source[index]) {
			index, line = skipRustToken(source, index, line)
			continue
		}
		start := index
		for index < len(source) && isRustIdentifierByte(source[index]) {
			index++
		}
		if start == index {
			tokens = append(tokens, rustPolicyToken{
				text: string(source[index]),
				line: line,
			})
			index++
			continue
		}
		tokens = append(tokens, rustPolicyToken{
			text: string(source[start:index]),
			line: line,
		})
	}
	return tokens, true
}

func rustAttributeSetsPath(source []byte) bool {
	tokens, valid := rustPolicyTokens(source)
	if !valid {
		return false
	}
	for index, token := range tokens {
		if token.text != "path" || index+1 >= len(tokens) ||
			tokens[index+1].text != "=" {
			continue
		}
		return true
	}
	return false
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
	if rustTokenStart(source[index]) {
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

func rustTokenStart(value byte) bool {
	switch value {
	case '"', '\'', 'r', 'b':
		return true
	default:
		return false
	}
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
			var valid bool
			index, line, valid = skipRustBlockComment(source, index, line)
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
	if end, ok := skipRustRawString(source, index); ok {
		return end, line + bytes.Count(source[index:end], []byte{'\n'})
	}
	if source[index] == 'b' && index+1 < len(source) &&
		(source[index+1] == '"' || source[index+1] == '\'') {
		index++
	}
	if source[index] == '\'' {
		return skipRustCharacter(source, index, line)
	}
	if source[index] != '"' {
		return index + 1, line
	}
	return skipRustString(source, index, line)
}

func skipRustString(source []byte, index, line int) (int, int) {
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
		} else if current == '"' {
			break
		}
	}
	return index, line
}

func skipRustRawString(source []byte, index int) (int, bool) {
	start := index
	if source[index] == 'b' {
		index++
	}
	if index >= len(source) || source[index] != 'r' {
		return start, false
	}
	index++
	hashes := 0
	for index < len(source) && source[index] == '#' {
		hashes++
		index++
	}
	if index >= len(source) || source[index] != '"' {
		return start, false
	}
	index++
	terminator := `"` + strings.Repeat("#", hashes)
	offset := bytes.Index(source[index:], []byte(terminator))
	if offset < 0 {
		return len(source), true
	}
	return index + offset + len(terminator), true
}

func skipRustCharacter(source []byte, index, line int) (int, int) {
	next := index + 1
	if next >= len(source) {
		return next, line
	}
	if source[next] == '\\' {
		next++
		for next < len(source) && source[next] != '\'' &&
			source[next] != '\n' {
			next++
		}
		if next < len(source) && source[next] == '\'' {
			return next + 1, line
		}
		return index + 1, line
	}
	_, size := utf8.DecodeRune(source[next:])
	if size > 0 && next+size < len(source) && source[next+size] == '\'' {
		return next + size + 1, line
	}
	return index + 1, line
}

func rustAttributeIdentifiers(source []byte) []string {
	var identifiers []string
	for index := 0; index < len(source); {
		if next, valid, found := rustAttributeComment(source, index); found {
			if !valid {
				return append(identifiers, "invalid_comment")
			}
			index = next
			continue
		}
		if source[index] == '"' || source[index] == '\'' ||
			source[index] == 'r' || source[index] == 'b' {
			next, _ := skipRustToken(source, index, 1)
			if next > index+1 {
				index = next
				continue
			}
		}
		if !isRustIdentifierByte(source[index]) {
			index++
			continue
		}
		start := index
		for index < len(source) && isRustIdentifierByte(source[index]) {
			index++
		}
		identifiers = append(identifiers, string(source[start:index]))
	}
	return identifiers
}

func rustAttributeComment(source []byte, index int) (int, bool, bool) {
	if index+1 >= len(source) || source[index] != '/' ||
		(source[index+1] != '/' && source[index+1] != '*') {
		return index, true, false
	}
	next, _, valid := skipRustTrivia(source, index, 1)
	return next, valid, true
}

func isRustIdentifierByte(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
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
