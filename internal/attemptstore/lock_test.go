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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"celestia.research/celestia/internal/operation/urlreference/transform"
	"celestia.research/celestia/internal/urladmission"
	"celestia.research/celestia/internal/workerprotocolv1"
)

const (
	lockHelperMode = "CELESTIA_LOCK_HELPER"
	lockHelperRoot = "CELESTIA_LOCK_ROOT"
)

func TestRecoverRejectsActiveAttempt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() {
		cleanupAttempt(t, attempt)
	})
	if err := store.Recover(accepted.Request.AttemptID, "active"); !errors.Is(err, ErrActive) {
		t.Fatalf("active attempt recovered: %v", err)
	}
	other, err := New(store.root)
	if err != nil {
		t.Fatalf("open second store: %v", err)
	}
	if err := other.Recover(accepted.Request.AttemptID, "active"); !errors.Is(err, ErrActive) {
		t.Fatalf("second store recovered active attempt: %v", err)
	}
}

func TestValidateAttemptLockRejectsIncompleteOwner(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	attemptID := accepted.Request.AttemptID
	key := filepath.Join(store.root, locksDirectory, attemptID+".lock")
	t.Cleanup(func() {
		activeAttemptLocks.Delete(key)
	})

	activeAttemptLocks.Store(key, struct{}{})
	if err := store.validateAttemptLock(attemptID); !errors.Is(err, ErrActive) {
		t.Fatalf("reserved attempt lock error = %v, want %v", err, ErrActive)
	}

	activeAttemptLocks.Store(key, &attemptLock{})
	if err := store.validateAttemptLock(attemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing owned attempt lock error = %v, want %v", err, ErrCorrupt)
	}
}

func TestStageCreatesOwnershipMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() {
		cleanupAttempt(t, attempt)
	})
	present, err := store.hasOwnershipMarker(accepted.Request.AttemptID)
	if err != nil || !present {
		t.Fatalf("ownership marker: present=%t error=%v", present, err)
	}
	if err := store.createOwnershipMarker(accepted.Request.AttemptID); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate ownership marker: %v", err)
	}
	markerPath := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.WriteFile(markerPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt ownership marker: %v", err)
	}
	if _, err := store.hasOwnershipMarker(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-empty ownership marker accepted: %v", err)
	}
}

func TestOwnershipMarkerRejectsDirectory(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	present, err := store.hasOwnershipMarker(accepted.Request.AttemptID)
	if err != nil || present {
		t.Fatalf("missing marker: present=%t error=%v", present, err)
	}
	path := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+ownershipMarkerSuffix,
	)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create marker directory: %v", err)
	}
	if _, err := store.hasOwnershipMarker(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("marker directory accepted: %v", err)
	}
}

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

func TestRootCloseFailureReleasesAttemptLock(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	first, err := store.acquireAttemptLock(accepted.Request.AttemptID, true)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	reservation := &lockReservation{key: first.key, keep: true}
	closeErr := errors.New("injected root close failure")
	lock, err := finishLockRootResult(closeErr, reservation, first, nil)
	if lock != nil || !errors.Is(err, closeErr) {
		t.Fatalf("lock=%v error=%v", lock, err)
	}
	second, err := store.acquireAttemptLock(accepted.Request.AttemptID, true)
	if err != nil {
		t.Fatalf("reacquire lock: %v", err)
	}
	if err := second.release(); err != nil {
		t.Fatalf("release second lock: %v", err)
	}
}

func TestStageRejectsLinkedLockFile(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	source := filepath.Join(store.root, "external-lock")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatalf("write linked lock source: %v", err)
	}
	target := filepath.Join(
		store.root,
		locksDirectory,
		accepted.Request.AttemptID+".lock",
	)
	if err := os.Link(source, target); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked lock accepted: %v", err)
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

func TestRecoverAfterOwnerProcessDeath(t *testing.T) {
	store, accepted, _ := lockProcessFixture(t)
	command := lockHelperCommand(t.Context(), "stage", store.root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "staged" {
		t.Fatalf(
			"helper did not stage: %v; cleanup: %v",
			scanner.Err(),
			stopLockHelper(command),
		)
	}
	if err := store.Recover(accepted.Request.AttemptID, "owner still active"); !errors.Is(err, ErrActive) {
		t.Fatalf(
			"recovered before owner death: %v; cleanup: %v",
			err,
			stopLockHelper(command),
		)
	}
	if err := stopLockHelper(command); err != nil {
		t.Fatalf("stop helper: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "owner process ended"); err != nil {
		t.Fatalf("recover after owner death: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect recovered attempt: %v", err)
	}
}

func TestRecoverAfterTerminalPublicationCrashPoints(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		published bool
	}{
		{name: "admitted", mode: "crash-admitted"},
		{name: "observation", mode: "crash-observation"},
		{name: "receipt", mode: "crash-receipt"},
		{name: "directory", mode: "crash-directory"},
		{name: "publication", mode: "crash-publication", published: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, accepted, _ := lockProcessFixture(t)
			command := lockHelperCommand(t.Context(), test.mode, store.root)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("crash helper exited successfully")
			}
			if len(output) != 0 {
				t.Fatalf("crash helper output: %s", output)
			}
			if test.published {
				assertPublishedCrash(t, store, accepted.Request.AttemptID)
				return
			}
			if err := store.Recover(
				accepted.Request.AttemptID, "abrupt owner death",
			); err != nil {
				t.Fatalf("Recover() error = %v", err)
			}
			if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
		})
	}
}

func TestRecoverCleansUncommittedCrashPoints(t *testing.T) {
	tests := []struct {
		mode        string
		recoverable bool
	}{
		{mode: "crash-lock"},
		{mode: "crash-pending-directory", recoverable: true},
		{mode: "crash-admitted-before-marker", recoverable: true},
	}
	for _, test := range tests {
		mode := test.mode
		t.Run(mode, func(t *testing.T) {
			store, accepted, admittedAt := lockProcessFixture(t)
			command := lockHelperCommand(t.Context(), mode, store.root)
			output, err := command.CombinedOutput()
			if err == nil || len(output) != 0 {
				t.Fatalf("crash helper error=%v output=%s", err, output)
			}
			recoveryErr := store.Recover(
				accepted.Request.AttemptID, "uncommitted stage",
			)
			if test.recoverable && !errors.Is(recoveryErr, ErrUncommitted) {
				t.Fatalf("Recover() error = %v", recoveryErr)
			}
			if !test.recoverable && !errors.Is(recoveryErr, os.ErrNotExist) {
				t.Fatalf("Recover() error = %v", recoveryErr)
			}
			attempt, err := store.Stage(accepted, admittedAt)
			if err != nil {
				t.Fatalf("Stage() after cleanup error = %v", err)
			}
			cleanupAttempt(t, attempt)
		})
	}
}

func assertPublishedCrash(t *testing.T, store *Store, attemptID string) {
	t.Helper()
	if err := store.Recover(attemptID, "already published"); !errors.Is(
		err, ErrDuplicate,
	) {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := store.Inspect(attemptID); err != nil {
		t.Fatalf("Inspect() error = %v", err)
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

func stopLockHelper(command *exec.Cmd) error {
	killErr := command.Process.Kill()
	if errors.Is(killErr, os.ErrProcessDone) {
		killErr = nil
	}
	waitErr := command.Wait()
	if exitErr, ok := errors.AsType[*exec.ExitError](waitErr); ok &&
		exitErr != nil {
		waitErr = nil
	}
	return errors.Join(killErr, waitErr)
}

func runUncommittedCrashHelper(
	t *testing.T,
	store *Store,
	accepted urladmission.Accepted,
	admittedAt time.Time,
	mode string,
) {
	t.Helper()
	request, err := validateAccepted(accepted, admittedAt)
	if err != nil {
		t.Fatalf("validate accepted: %v", err)
	}
	if _, err := store.acquireAttemptLock(request.AttemptID, true); err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	if mode == "crash-lock" {
		os.Exit(73)
	}
	_, path, err := store.prepareAttemptDirectories(
		request.AttemptID, createEvidenceDirectory,
	)
	if err != nil {
		t.Fatalf("prepare directories: %v", err)
	}
	if mode == "crash-admitted-before-marker" {
		if err := writeRecord(
			path, admittedFile,
			admittedRecord(request, accepted.Frame, admittedAt),
		); err != nil {
			t.Fatalf("write admitted: %v", err)
		}
	}
	os.Exit(73)
}

func runCrashHelper(
	t *testing.T,
	store *Store,
	accepted urladmission.Accepted,
	admittedAt time.Time,
	mode string,
) {
	t.Helper()
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if mode == "crash-admitted" {
		os.Exit(73)
	}
	observation := testObservationFor(t, accepted)
	if err := writeOrMatchRecord(
		attempt.path, observationFile, observation,
	); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if mode == "crash-observation" {
		os.Exit(73)
	}
	if err := writeOrMatchReceipt(
		attempt.path, accepted.Request.AttemptID, "observation",
		observationFile, observation.TerminalStatus,
	); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if mode == "crash-receipt" {
		os.Exit(73)
	}
	if _, err := attempt.publishDirectory(); err != nil {
		t.Fatalf("publish directory: %v", err)
	}
	if mode == "crash-directory" {
		os.Exit(73)
	}
	if err := publishMarker(
		store.finalPath(accepted.Request.AttemptID),
		accepted.Request.AttemptID,
	); err != nil {
		t.Fatalf("publish marker: %v", err)
	}
	os.Exit(73)
}

func lockHelperCommand(ctx context.Context, mode, root string) *exec.Cmd {
	// #nosec G204,G702 -- os.Args[0] is the current Go test binary.
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAttemptLockHelper$")
	command.Env = append(
		os.Environ(),
		lockHelperMode+"="+mode,
		lockHelperRoot+"="+root,
	)
	return command
}

func lockProcessFixture(t *testing.T) (*Store, urladmission.Accepted, time.Time) {
	t.Helper()
	root := os.Getenv(lockHelperRoot)
	if root == "" {
		root = newTestEvidenceRoot(t)
	}
	store, err := New(root)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	admittedAt := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	input := "https://example.com"
	inputHash := sha256.Sum256([]byte(input))
	request := workerprotocol.Request{
		ProtocolVersion:  workerprotocol.ProtocolVersion,
		OperationID:      workerprotocol.OperationID,
		OperationVersion: workerprotocol.OperationVersion,
		AttemptID:        base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)),
		RequestNonce:     base64.RawURLEncoding.EncodeToString(bytesOf(1)),
		InputMediaType:   workerprotocol.MediaType,
		InputLength:      len(input),
		InputSHA256:      hex.EncodeToString(inputHash[:]),
		Mode:             string(urlreference.Defang),
		Deadline: admittedAt.Add(
			time.Duration(workerprotocol.StartTimeoutMS) * time.Millisecond,
		).Format(time.RFC3339Nano),
		TimeoutMS: workerprotocol.TimeoutMS,
		Limits: workerprotocol.Limits{
			InputBytes:  workerprotocol.InputBytes,
			OutputBytes: workerprotocol.MaxOutputBytes,
			StderrBytes: workerprotocol.StderrBytes,
			MemoryBytes: workerprotocol.MemoryBytes,
			Processes:   workerprotocol.Processes,
		},
		Input: input,
	}
	frame, _, err := workerprotocol.EncodeRequest(request, admittedAt)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return store, urladmission.Accepted{Request: request, Frame: frame}, admittedAt
}

func bytesOf(value byte) []byte {
	data := make([]byte, sha256.Size)
	for index := range data {
		data[index] = value
	}
	return data
}
