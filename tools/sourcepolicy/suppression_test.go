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
	"strings"
	"testing"
)

func TestGoSuppressionFindings(t *testing.T) {
	source := []byte(strings.Join([]string{
		"// #no" + "sec",
		"// #no" + "sec G304 -- bounded repository source",
		"//no" + "lint",
		"//no" + "lint:errcheck -- checked by the owner",
		"//no" + "lint:all -- broad suppression",
		"// gosec:disable",
		"//gosec:enable",
		"//lint:ignore SA1000 retained finding",
		"//lint:file-ignore U1000 retained finding",
		"hash := md5.New() //gosec:disable",
		`text := "//gosec:disable"`,
	}, "\n"))
	findings := goSuppressionFindings("source.go", source)
	if len(findings) != 8 {
		t.Fatalf("findings = %v", findings)
	}
}
