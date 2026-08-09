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

package admission

import (
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxReplacementBytes = 1 << 20
	maxFilenameUnits    = 255
)

var (
	ErrTarget      = errors.New("invalid replacement target")
	ErrDigest      = errors.New("invalid precondition digest")
	ErrReplacement = errors.New("invalid replacement content")
)

// Input is the untrusted request supplied to admission.
type Input struct {
	Target         string
	ExpectedSHA256 string
	Replacement    []byte
}

// Request is an admitted immutable replacement request.
type Request struct {
	target      string
	expected    [32]byte
	replacement []byte
}

// Admit validates and copies one request.
func Admit(input Input) (Request, error) {
	if !validTarget(input.Target) {
		return Request{}, ErrTarget
	}
	expected, err := decodeDigest(input.ExpectedSHA256)
	if err != nil {
		return Request{}, err
	}
	if len(input.Replacement) > MaxReplacementBytes {
		return Request{}, ErrReplacement
	}
	return Request{
		target: input.Target, expected: expected,
		replacement: append([]byte(nil), input.Replacement...),
	}, nil
}

func (r Request) Target() string {
	return r.target
}

func (r Request) ExpectedSHA256() [32]byte {
	return r.expected
}

func (r Request) Replacement() []byte {
	return append([]byte(nil), r.replacement...)
}

func decodeDigest(value string) ([32]byte, error) {
	var digest [32]byte
	if len(value) != hex.EncodedLen(len(digest)) || strings.ToLower(value) != value {
		return digest, ErrDigest
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return digest, ErrDigest
	}
	copy(digest[:], decoded)
	return digest, nil
}

func validTarget(value string) bool {
	if value == "" || value == "." || value == ".." || !utf8.ValidString(value) ||
		strings.HasSuffix(value, ".") || strings.HasSuffix(value, " ") ||
		len(utf16.Encode([]rune(value))) > maxFilenameUnits {
		return false
	}
	for _, current := range value {
		if current < 0x20 || strings.ContainsRune(`<>:"/\|?*`, current) {
			return false
		}
	}
	stem, _, _ := strings.Cut(value, ".")
	return !reservedTarget(stem)
}

func reservedTarget(stem string) bool {
	reserved := []string{"CON", "PRN", "AUX", "NUL", "CLOCK$"}
	for _, name := range reserved {
		if strings.EqualFold(stem, name) {
			return true
		}
	}
	if len(stem) != 4 {
		return false
	}
	prefix := stem[:3]
	return (strings.EqualFold(prefix, "COM") || strings.EqualFold(prefix, "LPT")) &&
		stem[3] >= '1' && stem[3] <= '9'
}
