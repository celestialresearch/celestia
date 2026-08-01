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
	"errors"
	"testing"
)

func TestArchitectureShebangOwnership(t *testing.T) {
	t.Parallel()

	read := func(file string) ([]byte, error) {
		if file == "tools/sourcepolicy/rogue" ||
			file == "tools/sourcepolicy/rogue.txt" {
			return []byte("#!/usr/bin/env bash\n"), nil
		}
		return []byte("ordinary text\n"), nil
	}
	findings, err := architectureShebangFindings(
		[]string{"LICENSE", "tools/sourcepolicy/rogue", "tools/sourcepolicy/rogue.txt"},
		nil, read,
	)
	if err != nil || len(findings) != 2 ||
		findings[0] != "tools/sourcepolicy/rogue: script is not declared" ||
		findings[1] != "tools/sourcepolicy/rogue.txt: script is not declared" {
		t.Fatalf("findings = %v, error = %v", findings, err)
	}
	findings, err = architectureShebangFindings(
		[]string{"tools/sourcepolicy/rogue"},
		[]string{"tools/sourcepolicy/rogue"}, read,
	)
	if err != nil || len(findings) != 0 {
		t.Fatalf("declared findings = %v, error = %v", findings, err)
	}
}

func TestArchitectureShebangReadFailure(t *testing.T) {
	t.Parallel()

	_, err := architectureShebangFindings(
		[]string{"LICENSE"}, nil,
		func(string) ([]byte, error) { return nil, errors.New("read failed") },
	)
	if err == nil {
		t.Fatal("read failure accepted")
	}
}
