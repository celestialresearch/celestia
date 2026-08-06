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

//go:build windows || (linux && amd64)

package attemptstore

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"testing"
)

const (
	lockHelperMode = "CELESTIA_LOCK_HELPER"
	lockHelperRoot = "CELESTIA_LOCK_ROOT"
)

func TestReleasedAttemptCannotPublish(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release attempt: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("released attempt published: %v", err)
	}
}

func TestReleaseErrorPreservesCause(t *testing.T) {
	cause := errors.New("release fixture")
	err := releaseError(cause)
	if !errors.Is(err, ErrRelease) || !errors.Is(err, cause) {
		t.Fatalf("releaseError() error = %v", err)
	}
}

func TestAttemptLockCrossProcess(t *testing.T) {
	store, accepted, admittedAt := lockProcessFixture(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() {
		cleanupAttempt(t, attempt)
	})
	command := lockHelperCommand(t.Context(), "recover", store.root)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run recovery helper: %v: %s", err, output)
	}
	if !strings.Contains(string(output), "active\n") {
		t.Fatalf("helper output=%q", output)
	}
}

func TestAttemptLockHelper(t *testing.T) {
	mode := os.Getenv(lockHelperMode)
	if mode == "" {
		return
	}
	store, accepted, admittedAt := lockProcessFixture(t)
	attemptID := accepted.Request.AttemptID
	store, err := New(store.root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	switch mode {
	case "recover":
		if err := store.Recover(attemptID, "helper"); !errors.Is(err, ErrActive) {
			t.Fatalf("recover active attempt: %v", err)
		}
		fmt.Println("active")
	case "stage":
		attempt, err := store.Stage(accepted, admittedAt)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		defer func() {
			if err := attempt.Close(); err != nil {
				t.Errorf("close staged attempt: %v", err)
			}
		}()
		fmt.Println("staged")
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		defer signal.Stop(interrupt)
		<-interrupt
	case "crash-admitted", "crash-observation", "crash-receipt",
		"crash-directory", "crash-publication":
		runCrashHelper(t, store, accepted, admittedAt, mode)
	case "crash-lock", "crash-pending-directory", "crash-admitted-before-marker":
		runUncommittedCrashHelper(t, store, accepted, admittedAt, mode)
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func TestAttemptLockHelperRejectsUnknownMode(t *testing.T) {
	store, _, _ := lockProcessFixture(t)
	command := lockHelperCommand(t.Context(), "unknown", store.root)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("unknown helper mode succeeded")
	}
	if !strings.Contains(string(output), `unknown helper mode "unknown"`) {
		t.Fatalf("unexpected helper output: %q", output)
	}
}
