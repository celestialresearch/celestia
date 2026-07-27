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

//go:build js || plan9 || wasip1

package attemptstore

import (
	"errors"
	"testing"
)

func TestStoreRejectsUnsupportedPlatform(t *testing.T) {
	if _, err := New("/celestia-evidence"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported platform result: %v", err)
	}
	if err := secureEvidenceParent("/celestia"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported parent result: %v", err)
	}
}
