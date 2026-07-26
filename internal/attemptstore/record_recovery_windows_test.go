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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRepairInterruptedWindowsRecord(t *testing.T) {
	t.Parallel()

	path := filepath.Join(newTestStore(t).root, "records")
	if err := createEvidenceDirectory(path); err != nil {
		t.Fatal(err)
	}
	file, err := createRecordTemp(path, observationFile)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(file.Name())
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repairInterruptedRecords(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(path, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary record remains: %v", err)
	}
}
