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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	urladmission "celestia.research/celestia/internal/operation/urlreference/admission"
	workerprotocol "celestia.research/celestia/internal/operation/urlreference/protocol"
	urlreference "celestia.research/celestia/internal/operation/urlreference/transform"
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
