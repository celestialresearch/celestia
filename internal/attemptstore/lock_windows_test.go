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
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestActiveLockCannotBeReplacedWhileOwnerAlive(t *testing.T) {
	store, accepted, _ := lockProcessFixture(t)
	command := lockHelperCommand(t.Context(), "stage", store.root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	stopHelper := func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}
	defer stopHelper()
	if scanner := bufio.NewScanner(stdout); !scanner.Scan() || scanner.Text() != "staged" {
		t.Fatalf("helper did not stage: %v", scanner.Err())
	}

	lockPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Rename(lockPath, lockPath+".replacement"); err == nil {
		t.Fatal("active lock was replaceable while owner process was alive")
	}
	if err := store.Recover(accepted.Request.AttemptID, "owner still active"); !errors.Is(err, ErrActive) {
		t.Fatalf("active lock was not retained: %v", err)
	}

	stopHelper()
	if err := store.Recover(accepted.Request.AttemptID, "owner process ended"); err != nil {
		t.Fatalf("recover after owner death: %v", err)
	}
}
