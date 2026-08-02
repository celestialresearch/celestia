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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	urladmission "celestia.research/celestia/internal/operation/urlreference/admission"
	workerprotocol "celestia.research/celestia/internal/operation/urlreference/protocol"
	urlreference "celestia.research/celestia/internal/operation/urlreference/transform"
)

func TestRecoverPublishesAfterReceiptFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := writeOrMatchRecord(attempt.path, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "receipt write failed"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil ||
		records.Recovery != nil ||
		records.Observation.TerminalStatus != "verified" {
		t.Fatalf("records=%+v", records)
	}
}

func TestRecoverResumesRecoveryReceipt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted before receipt",
	}
	if err := writeOrMatchRecord(attempt.path, recoveryFile, recovery); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, recovery.Reason); err != nil {
		t.Fatalf("resume recovery: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Recovery == nil ||
		records.Observation != nil ||
		records.Recovery.Reason != recovery.Reason {
		t.Fatalf("records=%+v", records)
	}
}

func TestRecoverPublishesAfterMarkerFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := writeOrMatchRecord(attempt.path, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := writeOrMatchReceipt(
		attempt.path,
		accepted.Request.AttemptID,
		"observation",
		observationFile,
		observation.TerminalStatus,
	); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if _, err := attempt.publishDirectory(); err != nil {
		t.Fatalf("publish directory: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "marker write failed"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect: %v", err)
	}
}

func TestExistingTerminalRejectsContradiction(t *testing.T) {
	root := t.TempDir()
	accepted, _ := testAccepted(t)
	observation := testObservationFor(t, accepted)
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := writeRecord(root, observationFile, observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if err := writeRecord(root, recoveryFile, recovery); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	if err := publishExistingTerminal(root, accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("contradictory terminals accepted: %v", err)
	}
}

func TestExistingTerminalRejectsIdentityMismatch(t *testing.T) {
	accepted, _ := testAccepted(t)
	other, _ := testAccepted(t)
	tests := []struct {
		name  string
		file  string
		value any
	}{
		{
			name:  "observation",
			file:  observationFile,
			value: testObservationFor(t, other),
		},
		{
			name: "recovery",
			file: recoveryFile,
			value: Recovery{
				Version:        Version,
				AttemptID:      other.Request.AttemptID,
				TerminalStatus: "indeterminate",
				Reason:         "interrupted",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := writeRecord(root, test.file, test.value); err != nil {
				t.Fatalf("write terminal: %v", err)
			}
			if err := publishExistingTerminal(root, accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("mismatched terminal accepted: %v", err)
			}
		})
	}
}

func TestExistingTerminalRejectsMalformedSibling(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := testObservationFor(t, accepted)
	recovery := Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	tests := []struct {
		name       string
		validFile  string
		validValue any
		badFile    string
	}{
		{
			name:       "observation with malformed recovery",
			validFile:  observationFile,
			validValue: observation,
			badFile:    recoveryFile,
		},
		{
			name:       "recovery with malformed observation",
			validFile:  recoveryFile,
			validValue: recovery,
			badFile:    observationFile,
		},
		{
			name:    "malformed observation only",
			badFile: observationFile,
		},
		{
			name:    "malformed recovery only",
			badFile: recoveryFile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.validFile != "" {
				if err := writeRecord(root, test.validFile, test.validValue); err != nil {
					t.Fatalf("write valid terminal: %v", err)
				}
			}
			if err := os.WriteFile(
				filepath.Join(root, test.badFile),
				[]byte("{"),
				0o600,
			); err != nil {
				t.Fatalf("write malformed terminal: %v", err)
			}
			if err := publishExistingTerminal(
				root,
				accepted.Request.AttemptID,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("malformed terminal accepted: %v", err)
			}
		})
	}
}

func TestRecoverablePathRejectsInvalidIdentity(t *testing.T) {
	store := &Store{}
	if _, _, err := store.recoverablePath("invalid"); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("invalid recovery identity accepted: %v", err)
	}
}

func TestRecoverablePathPropagatesFilesystemFailure(t *testing.T) {
	store := &Store{root: "invalid\x00root"}
	attemptID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, err := store.recoverablePath(attemptID); err == nil {
		t.Fatal("invalid recovery path accepted")
	}
}

func TestRecoverablePathPropagatesPendingFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	target := t.TempDir()
	if err := os.Symlink(
		target,
		store.pendingPath(accepted.Request.AttemptID),
	); err != nil {
		t.Fatalf("link pending-path fixture: %v", err)
	}
	if _, _, err := store.recoverablePath(
		accepted.Request.AttemptID,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked pending path returned %v", err)
	}
}

func TestEnsureTerminalRejectsAdmittedIdentityMismatch(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	root := t.TempDir()
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	if err := writeRecord(root, admittedFile, admitted); err != nil {
		t.Fatal(err)
	}
	store := &Store{}
	if err := store.ensureTerminal(
		root,
		accepted.Request.RequestNonce,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched recovery identity accepted: %v", err)
	}
}

func TestEnsureTerminalRejectsCorruptExistingTerminal(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	root := protectedTestDirectory(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	if err := writeRecord(root, admittedFile, admitted); err != nil {
		t.Fatalf("write admitted record: %v", err)
	}
	if err := writeRecord(root, observationFile, map[string]bool{"invalid": true}); err != nil {
		t.Fatalf("write corrupt terminal: %v", err)
	}
	store := &Store{}
	if err := store.ensureTerminal(
		root,
		accepted.Request.AttemptID,
		"interrupted",
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt terminal accepted: %v", err)
	}
}

func TestStoreRejectsUnknownRecoveryIdentity(t *testing.T) {
	store := newTestStore(t)
	if err := store.Recover("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown recovery identity returned %v", err)
	}
}

func TestStoreRecoversPendingAttempt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Recovery == nil ||
		records.Observation != nil ||
		records.Receipt.TerminalState != "indeterminate" {
		t.Fatalf("records=%+v", records)
	}
	if err := store.Recover(accepted.Request.AttemptID, "again"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("repeat recovery: %v", err)
	}
}

func TestRecoveryRejectsInvalidReceiptState(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	receiptPath := filepath.Join(store.pendingPath(accepted.Request.AttemptID), bundleDirectory, receiptFile)
	if err := os.Mkdir(receiptPath, 0o700); err != nil {
		t.Fatalf("create receipt directory: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "interrupted"); err == nil {
		t.Fatal("invalid receipt state accepted recovery")
	}
}

func TestStoreRejectsIncompleteAttempts(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if _, err := store.Inspect(accepted.Request.AttemptID); err == nil {
		t.Fatal("pending attempt inspected as terminal")
	}
	if err := store.Recover(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"missing",
	); err == nil {
		t.Fatal("missing attempt recovered")
	}
}

func TestTerminalLoaderRejectsMismatches(t *testing.T) {
	root := t.TempDir()
	observation := testObservation("attempt")
	if err := writeRecord(root, "observation.json", observation); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	records := Records{Receipt: Receipt{
		AttemptID:     "other",
		TerminalKind:  "observation",
		TerminalFile:  "observation.json",
		TerminalState: observation.TerminalStatus,
	}}
	if err := loadTerminal(root, &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("observation mismatch: %v", err)
	}

	recovery := Recovery{
		Version:        Version,
		AttemptID:      "attempt",
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := writeRecord(root, "recovery.json", recovery); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	records = Records{Receipt: Receipt{
		AttemptID:     "other",
		TerminalKind:  "recovery",
		TerminalFile:  "recovery.json",
		TerminalState: recovery.TerminalStatus,
	}}
	if err := loadTerminal(root, &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("recovery mismatch: %v", err)
	}
	records = Records{Receipt: Receipt{
		AttemptID:     "attempt",
		TerminalKind:  "observation",
		TerminalFile:  "missing.json",
		TerminalState: "failed",
	}}
	if err := loadTerminal(root, &records); err == nil {
		t.Fatal("missing terminal accepted")
	}
}

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
