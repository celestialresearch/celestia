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
	"errors"
	"strings"
)

const (
	MaxInputBytes     = 4096
	MaxReferenceBytes = 8192
)

type Mode string

const (
	Fang   Mode = "fang"
	Defang Mode = "defang"
)

var errInvalid = errors.New("invalid URL reference")

func ValidateInput(input string) error {
	if len(input) > MaxInputBytes {
		return invalid("original input length")
	}
	_, err := parse(input)
	return err
}

func Transform(input string, mode Mode) (string, error) {
	if mode != Fang && mode != Defang {
		return "", invalid("unsupported mode")
	}
	ref, err := parse(input)
	if err != nil {
		return "", err
	}
	target := active
	if mode == Defang {
		target = defanged
	}
	if ref.state == target {
		return input, nil
	}
	scheme := input[:ref.schemeEnd]
	if target == active {
		scheme = strings.Replace(scheme, "xx", "tt", 1)
	} else {
		scheme = strings.Replace(scheme, "tt", "xx", 1)
	}
	host := input[ref.hostStart:ref.hostEnd]
	if ref.hostKind != hostNeutral {
		if target == active {
			host = strings.ReplaceAll(host, "[.]", ".")
		} else {
			host = strings.ReplaceAll(host, ".", "[.]")
		}
	}
	output := scheme + input[ref.schemeEnd:ref.hostStart] + host + input[ref.hostEnd:]
	if len(output) > MaxReferenceBytes {
		return "", invalid("output length")
	}
	return output, nil
}
