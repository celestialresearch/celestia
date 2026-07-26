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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package attemptstore

import (
	"path/filepath"
	"testing"
)

func TestRecordTempSupportsRecovery(t *testing.T) {
	t.Parallel()

	file, err := createRecordTemp(t.TempDir(), admittedFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if name := filepath.Base(file.Name()); !temporaryRecordName(admittedFile, name) {
		t.Fatalf("createRecordTemp() name = %q is not recoverable", name)
	}
}
