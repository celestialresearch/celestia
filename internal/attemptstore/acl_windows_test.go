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

//go:build windows

package attemptstore

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestEvidenceACERejectsInvalidSID(t *testing.T) {
	t.Parallel()

	expected, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID() error = %v", err)
	}
	ace := windows.ACCESS_ALLOWED_ACE{}
	ace.Header.AceSize = uint16(unsafe.Offsetof(ace.SidStart) + 8)
	if evidenceACEIdentifies(&ace, expected) {
		t.Fatal("invalid SID accepted")
	}
}
