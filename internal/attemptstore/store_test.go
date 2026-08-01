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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"celestia.research/celestia/internal/urladmission"
	"celestia.research/celestia/internal/urlreferencev1"
	"celestia.research/celestia/internal/workerprotocolv1"
)

func TestStoreRejectsInvalidEvidenceRoots(t *testing.T) {
	for _, root := range []string{"", "relative-evidence-root"} {
		t.Run(root, func(t *testing.T) {
			if _, err := New(root); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid evidence root accepted: %v", err)
			}
		})
	}
	file := filepath.Join(t.TempDir(), "evidence")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write file root: %v", err)
	}
	if _, err := New(file); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("file evidence root accepted: %v", err)
	}
	nested := filepath.Join(t.TempDir(), "missing", "evidence")
	if _, err := New(nested); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing evidence parent accepted: %v", err)
	}
	root := newTestEvidenceRoot(t)
	if _, err := New(root); err != nil {
		t.Fatalf("existing evidence parent rejected: %v", err)
	}
}

func TestStoreRejectsPendingPathReplacementDuringCleanup(t *testing.T) {
	if err := removePendingDirectory(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("missing pending path: %v", err)
	}
	directory := filepath.Join(t.TempDir(), "pending-directory")
	if err := createEvidenceDirectory(directory); err != nil {
		t.Fatalf("create pending directory: %v", err)
	}
	if err := removePendingDirectory(directory); err != nil {
		t.Fatalf("remove pending directory: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pending")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write pending replacement: %v", err)
	}
	if err := removePendingDirectory(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("pending file replacement accepted: %v", err)
	}
}

func TestStoreRejectsUnknownRecoveryIdentity(t *testing.T) {
	store := newTestStore(t)
	if err := store.Recover("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown recovery identity returned %v", err)
	}
}

func TestStoreRejectsRecordOutsideEvidenceBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-bundle")
	if err := writeRecord(path, admittedFile, Admitted{}); err == nil {
		t.Fatal("record written outside an evidence bundle")
	}
}

func TestStoreRejectsUnserialisableRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle")
	if err := createEvidenceDirectory(path); err != nil {
		t.Fatalf("create record bundle: %v", err)
	}
	if err := writeRecord(path, "invalid.json", make(chan int)); err == nil {
		t.Fatal("unserialisable record accepted")
	}
}

func TestStorePublishesAndInspects(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	observation := testObservationFor(t, accepted)
	if err := attempt.Publish(observation); err != nil {
		t.Fatalf("publish: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if records.Observation == nil ||
		records.Recovery != nil ||
		records.Admitted.OriginalInput != accepted.Request.Input ||
		string(records.Admitted.RequestFrame) != string(accepted.Frame) ||
		records.Observation.TerminalStatus != "verified" {
		t.Fatalf("records=%+v", records)
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

func TestStoreRejectsDuplicateAndInvalidRecords(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate stage: %v", err)
	}
	observation := testObservation("invalid")
	if err := attempt.Publish(observation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid observation: %v", err)
	}
	observation = testObservation(accepted.Request.AttemptID)
	if err := attempt.Publish(observation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("released attempt published: %v", err)
	}
	for _, reason := range []string{
		"",
		" ",
		"line\nbreak",
		string([]byte{0xff}),
		strings.Repeat("x", maxRecoveryReasonBytes+1),
	} {
		if err := store.Recover(accepted.Request.AttemptID, reason); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid recovery reason %q: %v", reason, err)
		}
	}
	if _, err := store.Inspect("invalid"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid identity: %v", err)
	}
	if _, err := store.Inspect(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical identity: %v", err)
	}
}

func TestStoreDetectsCorruption(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("stage published attempt: %v", err)
	}
	path := filepath.Join(store.finalPath(accepted.Request.AttemptID), observationFile)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("corrupt observation: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inspect corruption: %v", err)
	}
}

func TestStoreRejectsReceiptPathSubstitution(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	receiptPath := filepath.Join(store.finalPath(accepted.Request.AttemptID), receiptFile)
	root, err := os.OpenRoot(filepath.Dir(receiptPath))
	if err != nil {
		t.Fatalf("open attempt root: %v", err)
	}
	data, err := func() (data []byte, returnedErr error) {
		defer func() {
			returnedErr = errors.Join(returnedErr, root.Close())
		}()
		file, openErr := root.Open(filepath.Base(receiptPath))
		if openErr != nil {
			return nil, openErr
		}
		defer func() {
			returnedErr = errors.Join(returnedErr, file.Close())
		}()
		return io.ReadAll(file)
	}()
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var receipt Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	receipt.TerminalFile = "../outside"
	changed, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	if err := os.WriteFile(receiptPath, changed, 0o600); err != nil {
		t.Fatalf("replace receipt: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("path substitution: %v", err)
	}
}

func TestStoreRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New("relative"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative root: %v", err)
	}
	rootFile := filepath.Join(t.TempDir(), "root")
	if err := os.WriteFile(rootFile, []byte("file"), 0o600); err != nil {
		t.Fatalf("write root file: %v", err)
	}
	if _, err := New(rootFile); err == nil {
		t.Fatal("file accepted as evidence root")
	}
	accepted, admittedAt := testAccepted(t)
	store := newTestStore(t)
	invalidAccepted := accepted
	invalidAccepted.Frame = nil
	if _, err := store.Stage(invalidAccepted, admittedAt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty frame: %v", err)
	}
	admittedAt = admittedAt.Local()
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("local time: %v", err)
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

func TestStoreReportsWriteFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if err := os.Rename(attempt.path, attempt.path+".moved"); err != nil {
		t.Fatalf("move attempt: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err == nil {
		t.Fatal("missing attempt directory accepted publication")
	}
}

func TestStoreRejectsMalformedRecords(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	path := store.finalPath(accepted.Request.AttemptID)
	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "admitted JSON", file: "admitted.json", data: []byte("{")},
		{name: "receipt JSON", file: "receipt.json", data: []byte("{}{}")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(path, test.file)
			original, readErr := readRooted(path, test.file)
			if readErr != nil {
				t.Fatalf("read record: %v", readErr)
			}
			if writeErr := os.WriteFile(target, test.data, 0o600); writeErr != nil {
				t.Fatalf("write malformed record: %v", writeErr)
			}
			if _, inspectErr := store.Inspect(accepted.Request.AttemptID); inspectErr == nil {
				t.Fatal("malformed record was accepted")
			}
			if writeErr := os.WriteFile(target, original, 0o600); writeErr != nil {
				t.Fatalf("restore record: %v", writeErr)
			}
		})
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

func TestStoreRejectsReceiptVariants(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Receipt)
	}{
		{name: "attempt", change: func(receipt *Receipt) { receipt.AttemptID = "invalid" }},
		{name: "admitted file", change: func(receipt *Receipt) { receipt.AdmittedFile = "other" }},
		{name: "kind", change: func(receipt *Receipt) { receipt.TerminalKind = "other" }},
		{name: "observation file", change: func(receipt *Receipt) { receipt.TerminalFile = "other" }},
		{
			name: "recovery file",
			change: func(receipt *Receipt) {
				receipt.TerminalKind = "recovery"
				receipt.TerminalFile = "other"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			accepted, admittedAt := testAccepted(t)
			attempt, err := store.Stage(accepted, admittedAt)
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
				t.Fatalf("publish: %v", err)
			}
			path := store.finalPath(accepted.Request.AttemptID)
			var receipt Receipt
			if err := readRecord(path, "receipt.json", &receipt); err != nil {
				t.Fatalf("read receipt: %v", err)
			}
			test.change(&receipt)
			data, err := json.Marshal(receipt)
			if err != nil {
				t.Fatalf("encode receipt: %v", err)
			}
			if err := os.WriteFile(filepath.Join(path, "receipt.json"), data, 0o600); err != nil {
				t.Fatalf("replace receipt: %v", err)
			}
			if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("variant accepted: %v", err)
			}
		})
	}
}

func TestRootedReadRejectsNonFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := readRooted(root, "."); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory read: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create record symlink: %v", err)
	}
	if _, err := readRooted(root, "link"); err == nil {
		t.Fatal("symlink read was accepted")
	}
}

func TestWriteRecordRejectsDuplicate(t *testing.T) {
	root := t.TempDir()
	if err := writeRecord(root, "record.json", map[string]int{"value": 1}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeRecord(root, "record.json", map[string]int{"value": 2}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate write: %v", err)
	}
	if err := writeRecord(filepath.Join(root, "missing"), "record.json", struct{}{}); err == nil {
		t.Fatal("missing directory accepted write")
	}
}

func TestWriteRecordRejectsOversizedEncodingBeforeTemporaryFile(t *testing.T) {
	root := t.TempDir()
	if err := writeRecord(root, "large.json", strings.Repeat("x", maxRecordBytes)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized record: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(root, ".large.json.*"))
	if err != nil {
		t.Fatalf("glob temporary records: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("oversized record left temporary files: %v", matches)
	}
}

func TestRecordValidators(t *testing.T) {
	for _, status := range []string{
		"failed",
		"cancelled",
		"timed_out",
		"executed_unverified",
		"verified",
		"indeterminate",
	} {
		if !validTerminal(status) {
			t.Fatalf("valid terminal status %q rejected", status)
		}
	}
	if validTerminal("unknown") || validHash("not-a-hash") {
		t.Fatal("invalid record metadata accepted")
	}
	if err := writeRecord(t.TempDir(), "invalid.json", make(chan int)); err == nil {
		t.Fatal("unserialisable record accepted")
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

func TestHashHelpersRejectMissingAndMismatch(t *testing.T) {
	root := t.TempDir()
	if _, err := fileHash(root, "missing"); err == nil {
		t.Fatal("missing file was hashed")
	}
	if err := os.WriteFile(filepath.Join(root, "record"), []byte("record"), 0o600); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := verifyHash(root, "record", "wrong"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("hash mismatch: %v", err)
	}
	accepted, admittedAt := testAccepted(t)
	admitted := Admitted{
		Version:       Version,
		AttemptID:     accepted.Request.AttemptID,
		AdmittedAt:    admittedAt.Format(time.RFC3339Nano),
		OriginalInput: accepted.Request.Input,
		RequestFrame:  accepted.Frame,
	}
	if err := writeRecord(root, admittedFile, admitted); err != nil {
		t.Fatalf("write admitted: %v", err)
	}
	if err := writeOrMatchReceipt(
		root,
		accepted.Request.AttemptID,
		"observation",
		"missing",
		"failed",
	); err == nil {
		t.Fatal("missing terminal record published")
	}
	if _, err := readRooted(filepath.Join(root, "missing"), "record"); err == nil {
		t.Fatal("missing root accepted")
	}
}

func TestAttemptPathRejectsFile(t *testing.T) {
	store := newTestStore(t)
	attemptID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := os.WriteFile(store.finalPath(attemptID), []byte("file"), 0o600); err != nil {
		t.Fatalf("write attempt file: %v", err)
	}
	if _, err := store.attemptPath(attemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("attempt file: %v", err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(newTestEvidenceRoot(t))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func cleanupAttempt(t *testing.T, attempt *Attempt) {
	t.Helper()
	t.Cleanup(func() {
		if err := attempt.Close(); err != nil {
			t.Errorf("close attempt: %v", err)
		}
	})
}

func newTestEvidenceRoot(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "owned")
	if err := createEvidenceDirectory(parent); err != nil {
		t.Fatalf("create evidence parent: %v", err)
	}
	return filepath.Join(parent, "evidence")
}

func testAccepted(tb testing.TB) (urladmission.Accepted, time.Time) {
	tb.Helper()
	admittedAt := time.Now().UTC()
	accepted, err := urladmission.Admit(
		"https://example.test/path",
		urlreference.Defang,
		admittedAt,
	)
	if err != nil {
		tb.Fatalf("admit: %v", err)
	}
	return accepted, admittedAt
}

func testObservation(attemptID string) Observation {
	workerHash := sha256.Sum256([]byte("worker"))
	return Observation{
		Version:          Version,
		AttemptID:        attemptID,
		WorkerSHA256:     hex.EncodeToString(workerHash[:]),
		ProcessStatus:    "completed",
		Stdout:           []byte("response"),
		CleanupComplete:  true,
		ProtocolStatus:   "valid",
		VerificationID:   "go-url-reference",
		VerificationVer:  URLVerifierVersion,
		ExpectedOutput:   "hxxps://example[.]test/path",
		VerificationPass: true,
		TerminalStatus:   "verified",
		DurationNS:       1,
	}
}

func testObservationFor(tb testing.TB, accepted urladmission.Accepted) Observation {
	tb.Helper()
	observation := testObservation(accepted.Request.AttemptID)
	output, err := urlreference.Transform(
		accepted.Request.Input,
		urlreference.Mode(accepted.Request.Mode),
	)
	if err != nil {
		tb.Fatalf("transform response fixture: %v", err)
	}
	observation.ExpectedOutput = output
	mediaType := workerprotocol.MediaType
	outputLength := len(output)
	outputHash := sha256.Sum256([]byte(output))
	outputHashText := hex.EncodeToString(outputHash[:])
	response := workerprotocol.Response{
		ProtocolVersion:  workerprotocol.ProtocolVersion,
		OperationID:      workerprotocol.OperationID,
		OperationVersion: workerprotocol.OperationVersion,
		AttemptID:        accepted.Request.AttemptID,
		RequestNonce:     accepted.Request.RequestNonce,
		WorkerID:         workerprotocol.WorkerID,
		WorkerVersion:    workerprotocol.WorkerVersion,
		Status:           workerprotocol.Completed,
		OutputMediaType:  &mediaType,
		OutputLength:     &outputLength,
		OutputSHA256:     &outputHashText,
		Output:           &output,
		Diagnostics:      []workerprotocol.Diagnostic{},
		DurationNS:       1,
	}
	observation.Stdout, err = json.Marshal(response)
	if err != nil {
		tb.Fatalf("encode response fixture: %v", err)
	}
	return observation
}
