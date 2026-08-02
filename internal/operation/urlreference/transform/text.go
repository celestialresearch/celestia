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

package urlreference

import (
	"fmt"
	"unicode/utf8"
)

func validateInput(input string) error {
	if len(input) == 0 || len(input) > MaxReferenceBytes {
		return invalid("input length")
	}
	if !utf8.ValidString(input) {
		return invalid("UTF-8")
	}
	for _, character := range input {
		if character < 0x20 || character == 0x7f || rejectedSpace(character) {
			return invalid("control or whitespace")
		}
	}
	return nil
}

func rejectedSpace(character rune) bool {
	return character == 0x20 ||
		character == 0x85 ||
		character == 0xA0 ||
		character == 0x1680 ||
		character >= 0x2000 && character <= 0x200A ||
		character == 0x2028 ||
		character == 0x2029 ||
		character == 0x202F ||
		character == 0x205F ||
		character == 0x3000 ||
		character == 0xFEFF
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isHex(value byte) bool {
	return isDigit(value) ||
		value >= 'A' && value <= 'F' ||
		value >= 'a' && value <= 'f'
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, reason)
}
