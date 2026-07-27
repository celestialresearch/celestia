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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows

package attemptstore

import "testing"

func TestRecordTempNameSupportsRecovery(t *testing.T) {
	t.Parallel()

	name, err := recordTempName(admittedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !temporaryRecordName(admittedFile, name) {
		t.Fatalf("recordTempName() = %q is not recoverable", name)
	}
}
