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

import "testing"

func TestOrdinaryTestMainIsNotCandidate(t *testing.T) {
	t.Parallel()
	candidate, err := hasGoPolicySelector(
		"fixture.go",
		[]byte("package fixture\nfunc TestMain() {}\n"),
	)
	if err != nil || candidate {
		t.Fatalf("ordinary TestMain candidate = %t, error = %v", candidate, err)
	}
}
