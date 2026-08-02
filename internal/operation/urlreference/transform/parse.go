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

import "strings"

type state uint8

const (
	active state = iota
	defanged
)

type reference struct {
	schemeEnd int
	hostStart int
	hostEnd   int
	state     state
	hostKind  hostKind
}

func parse(input string) (reference, error) {
	if err := validateInput(input); err != nil {
		return reference{}, err
	}
	schemeEnd := strings.Index(input, "://")
	if schemeEnd < 0 {
		return reference{}, invalid("scheme delimiter")
	}
	schemeState, ok := schemeClass(input[:schemeEnd])
	if !ok {
		return reference{}, invalid("scheme")
	}
	return parseReference(input, schemeEnd, schemeState)
}

func parseReference(input string, schemeEnd int, schemeState state) (reference, error) {
	authorityStart := schemeEnd + 3
	authorityEnd := suffixStart(input, authorityStart)
	if authorityEnd == authorityStart {
		return reference{}, invalid("empty authority")
	}
	if err := validateSuffix(input[authorityEnd:]); err != nil {
		return reference{}, err
	}
	hostText, hostStart, hostEnd, err := splitAuthority(input, authorityStart, authorityEnd)
	if err != nil {
		return reference{}, err
	}
	hostState, kind, err := classifyHost(hostText)
	if err != nil {
		return reference{}, err
	}
	if kind != hostNeutral && hostState != schemeState {
		return reference{}, invalid("mixed transformation state")
	}
	return reference{
		schemeEnd: schemeEnd,
		hostStart: hostStart,
		hostEnd:   hostEnd,
		state:     schemeState,
		hostKind:  kind,
	}, nil
}

func schemeClass(scheme string) (state, bool) {
	switch scheme {
	case "http", "https":
		return active, true
	case "hxxp", "hxxps":
		return defanged, true
	default:
		return 0, false
	}
}

func suffixStart(input string, start int) int {
	end := len(input)
	for _, delimiter := range []byte{'/', '?', '#'} {
		if index := strings.IndexByte(input[start:], delimiter); index >= 0 {
			end = min(end, start+index)
		}
	}
	return end
}

func validateSuffix(suffix string) error {
	for index := 0; index < len(suffix); index++ {
		if suffix[index] != '%' {
			continue
		}
		if index+2 >= len(suffix) || !isHex(suffix[index+1]) || !isHex(suffix[index+2]) {
			return invalid("percent triplet")
		}
		index += 2
	}
	return nil
}
