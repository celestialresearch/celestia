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

	"celestia.research/governed-operation/internal/urladmission"
	"celestia.research/governed-operation/internal/urlreference"
	"celestia.research/governed-operation/internal/workerprotocol"
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
	defer func() {
		_ = attempt.Close()
	}()
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

func TestStageCreatesOwnershipMarker(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer func() {
		_ = attempt.Close()
	}()
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
	if legacy, err := store.legacyLockMissing("invalid"); err != nil || legacy {
		t.Fatalf("invalid identity classified as legacy: legacy=%t error=%v", legacy, err)
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
	if err := attempt.Publish(testObservation(accepted.Request.AttemptID)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("released attempt published: %v", err)
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
		t.Skipf("hard links unavailable: %v", err)
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
	defer func() {
		_ = attempt.Close()
	}()
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
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("helper did not stage: %v", scanner.Err())
	}
	if err := store.Recover(accepted.Request.AttemptID, "owner still active"); !errors.Is(err, ErrActive) {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("recovered before owner death: %v", err)
	}
	_ = command.Process.Kill()
	if err := command.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}
	if err := store.Recover(accepted.Request.AttemptID, "owner process ended"); err != nil {
		t.Fatalf("recover after owner death: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect recovered attempt: %v", err)
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
			_ = attempt.Close()
		}()
		fmt.Println("staged")
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		defer signal.Stop(interrupt)
		<-interrupt
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
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
		root = filepath.Join(t.TempDir(), "evidence")
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
			time.Duration(workerprotocol.TimeoutMS) * time.Millisecond,
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
