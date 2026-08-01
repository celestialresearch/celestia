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
	"io/fs"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

func validArchitecturePath(file string) bool {
	if path.Clean(file) != file || !fs.ValidPath(file) || !utf8.ValidString(file) ||
		!validWindowsArchitecturePath(file) {
		return false
	}
	return strings.IndexFunc(file, func(character rune) bool {
		return unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) || unicode.Is(unicode.Zp, character)
	}) == -1
}

func validWindowsArchitecturePath(file string) bool {
	for segment := range strings.SplitSeq(file, "/") {
		if strings.ContainsAny(segment, `<>:"\|?*`) ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") ||
			windowsReservedName(segment) {
			return false
		}
	}
	return true
}

func windowsReservedName(segment string) bool {
	name := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
	if slices.Contains(
		[]string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"},
		name,
	) {
		return true
	}
	suffix := ""
	if after, ok := strings.CutPrefix(name, "COM"); ok {
		suffix = after
	} else if after, ok := strings.CutPrefix(name, "LPT"); ok {
		suffix = after
	} else {
		return false
	}
	if len([]rune(suffix)) != 1 {
		return false
	}
	character, _ := utf8.DecodeRuneInString(suffix)
	return slices.Contains([]rune("123456789¹²³"), character)
}
