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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"celestia.research/governed-operation/internal/workerprotocol"
)

func TestStageRejectsAcceptedFrameMismatch(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	other, _ := testAccepted(t)
	tests := []struct {
		name   string
		change func(*workerprotocol.Request)
	}{
		{name: "protocol", change: func(request *workerprotocol.Request) { request.ProtocolVersion++ }},
		{name: "operation", change: func(request *workerprotocol.Request) { request.OperationID = "other" }},
		{name: "operation version", change: func(request *workerprotocol.Request) { request.OperationVersion++ }},
		{name: "attempt", change: func(request *workerprotocol.Request) { request.AttemptID = other.Request.AttemptID }},
		{name: "nonce", change: func(request *workerprotocol.Request) { request.RequestNonce = other.Request.RequestNonce }},
		{name: "media", change: func(request *workerprotocol.Request) { request.InputMediaType = "application/json" }},
		{name: "length", change: func(request *workerprotocol.Request) { request.InputLength++ }},
		{name: "hash", change: func(request *workerprotocol.Request) { request.InputSHA256 = zeroHash() }},
		{name: "mode", change: func(request *workerprotocol.Request) { request.Mode = "fang" }},
		{name: "deadline", change: func(request *workerprotocol.Request) {
			request.Deadline = admittedAt.Add(time.Second).Format(time.RFC3339Nano)
		}},
		{name: "timeout", change: func(request *workerprotocol.Request) { request.TimeoutMS++ }},
		{name: "limits", change: func(request *workerprotocol.Request) { request.Limits.OutputBytes++ }},
		{name: "input", change: func(request *workerprotocol.Request) { bindRequestInput(request, "https://other.test/path") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := accepted
			request := accepted.Request
			test.change(&request)
			changed.Request = request
			if _, err := newTestStore(t).Stage(changed, admittedAt); !errors.Is(err, ErrInvalid) {
				t.Fatalf("mismatched accepted request staged: %v", err)
			}
		})
	}
}

func TestPublishRejectsUnverifiableProtocolEvidence(t *testing.T) {
	tests := map[string]func(*Observation){
		"response": func(observation *Observation) {
			observation.Stdout = []byte(`{"status":"completed"}`)
		},
		"verifier": func(observation *Observation) {
			observation.VerificationID = "other"
		},
		"expected output": func(observation *Observation) {
			observation.ExpectedOutput = "hxxps://other[.]test/"
		},
		"verification result": func(observation *Observation) {
			observation.VerificationPass = false
			observation.TerminalStatus = "executed_unverified"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			accepted, admittedAt := testAccepted(t)
			attempt, err := store.Stage(accepted, admittedAt)
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			t.Cleanup(func() { _ = attempt.Close() })
			observation := testObservationFor(t, accepted)
			mutate(&observation)
			if err := attempt.Publish(observation); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unverifiable protocol evidence accepted: %v", err)
			}
		})
	}
}

func TestInspectRejectsProtocolEvidenceCorruption(t *testing.T) {
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
	replaceJSONField(t, filepath.Join(path, observationFile), "stdout", []byte(`{}`))
	refreshPublicationHashes(t, path)

	if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt protocol evidence accepted: %v", err)
	}
}

func TestInspectRejectsAdmittedBindingCorruption(t *testing.T) {
	tests := admittedCorruptionTests()
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
			test.corrupt(t, path, accepted, admittedAt)
			refreshPublicationHashes(t, path)
			if _, err := store.Inspect(accepted.Request.AttemptID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("admitted corruption accepted: %v", err)
			}
		})
	}
}

func TestRecoverRejectsAdmittedBindingCorruption(t *testing.T) {
	tests := []admittedCorruption{
		{
			name: "field input",
			corrupt: func(t *testing.T, path string, _ acceptedAttempt, _ time.Time) {
				t.Helper()
				replaceJSONField(t, filepath.Join(path, admittedFile), "original_input", "https://other.test/path")
			},
		},
		{
			name: "frame hash",
			corrupt: func(t *testing.T, path string, accepted acceptedAttempt, _ time.Time) {
				t.Helper()
				request := accepted.Request
				request.InputSHA256 = zeroHash()
				replaceAdmittedFrame(t, path, rawFrame(t, request))
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
			path := filepath.Join(store.pendingPath(accepted.Request.AttemptID), bundleDirectory)
			test.corrupt(t, path, acceptedAttempt(accepted), admittedAt)
			if err := attempt.Close(); err != nil {
				t.Fatalf("release attempt: %v", err)
			}
			if err := store.Recover(accepted.Request.AttemptID, "interrupted"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("recovered corrupt admitted record: %v", err)
			}
		})
	}
}

type acceptedAttempt = struct {
	Request workerprotocol.Request
	Frame   []byte
}

type admittedCorruption struct {
	name    string
	corrupt func(*testing.T, string, acceptedAttempt, time.Time)
}

func admittedCorruptionTests() []admittedCorruption {
	return []admittedCorruption{
		{
			name: "field attempt",
			corrupt: func(t *testing.T, path string, _ acceptedAttempt, _ time.Time) {
				t.Helper()
				other, _ := testAccepted(t)
				replaceJSONField(t, filepath.Join(path, admittedFile), "attempt_id", other.Request.AttemptID)
			},
		},
		{
			name: "field input",
			corrupt: func(t *testing.T, path string, _ acceptedAttempt, _ time.Time) {
				t.Helper()
				replaceJSONField(t, filepath.Join(path, admittedFile), "original_input", "https://other.test/path")
			},
		},
		{
			name: "frame attempt",
			corrupt: func(t *testing.T, path string, accepted acceptedAttempt, admittedAt time.Time) {
				t.Helper()
				other, _ := testAccepted(t)
				request := accepted.Request
				request.AttemptID = other.Request.AttemptID
				replaceAdmittedFrame(t, path, validFrame(t, request, admittedAt))
			},
		},
		{
			name: "frame input",
			corrupt: func(t *testing.T, path string, accepted acceptedAttempt, admittedAt time.Time) {
				t.Helper()
				request := accepted.Request
				bindRequestInput(&request, "https://other.test/path")
				replaceAdmittedFrame(t, path, validFrame(t, request, admittedAt))
			},
		},
		{name: "deadline", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.Deadline = request.Deadline + "0" })},
		{name: "length", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.InputLength++ })},
		{name: "hash", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.InputSHA256 = zeroHash() })},
		{name: "mode", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.Mode = "other" })},
		{name: "protocol", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.ProtocolVersion++ })},
		{name: "operation", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.OperationID = "other" })},
		{name: "operation version", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.OperationVersion++ })},
		{name: "media", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.InputMediaType = "application/json" })},
		{name: "timeout", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.TimeoutMS++ })},
		{name: "limits", corrupt: corruptRequest(func(request *workerprotocol.Request) { request.Limits.InputBytes++ })},
	}
}

func corruptRequest(change func(*workerprotocol.Request)) func(*testing.T, string, acceptedAttempt, time.Time) {
	return func(t *testing.T, path string, accepted acceptedAttempt, _ time.Time) {
		t.Helper()
		request := accepted.Request
		change(&request)
		replaceAdmittedFrame(t, path, rawFrame(t, request))
	}
}

func replaceAdmittedFrame(t *testing.T, path string, frame []byte) {
	t.Helper()
	replaceJSONField(t, filepath.Join(path, admittedFile), "request_frame", frame)
}

func rawFrame(t *testing.T, request workerprotocol.Request) []byte {
	t.Helper()
	frame, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode request frame: %v", err)
	}
	return frame
}

func validFrame(t *testing.T, request workerprotocol.Request, admittedAt time.Time) []byte {
	t.Helper()
	frame, _, err := workerprotocol.EncodeRequest(request, admittedAt)
	if err != nil {
		t.Fatalf("encode valid request: %v", err)
	}
	return frame
}

func refreshPublicationHashes(t *testing.T, path string) {
	t.Helper()
	var receipt Receipt
	readJSONFile(t, filepath.Join(path, receiptFile), &receipt)
	admittedHash, err := fileHash(path, admittedFile)
	if err != nil {
		t.Fatalf("hash admitted: %v", err)
	}
	terminalHash, err := fileHash(path, receipt.TerminalFile)
	if err != nil {
		t.Fatalf("hash terminal: %v", err)
	}
	receipt.AdmittedHash = admittedHash
	receipt.TerminalHash = terminalHash
	writeJSONFile(t, filepath.Join(path, receiptFile), receipt)
	receiptHash, err := fileHash(path, receiptFile)
	if err != nil {
		t.Fatalf("hash receipt: %v", err)
	}
	var publication Publication
	readJSONFile(t, filepath.Join(path, publicationFile), &publication)
	publication.ReceiptHash = receiptHash
	writeJSONFile(t, filepath.Join(path, publicationFile), publication)
}

func bindRequestInput(request *workerprotocol.Request, input string) {
	hash := sha256.Sum256([]byte(input))
	request.Input = input
	request.InputLength = len(input)
	request.InputSHA256 = hex.EncodeToString(hash[:])
}

func zeroHash() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}
