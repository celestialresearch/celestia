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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"celestia.research/celestia/internal/workerprotocolv1"
)

func TestBundleRejectsUnexpectedRegularEntry(t *testing.T) {
	path := t.TempDir()
	for _, name := range []string{admittedFile, observationFile, "unexpected.json"} {
		if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := validateBundleFiles(path, observationFile, false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unexpected record accepted: %v", err)
	}
}

func TestReceiptValidationRejectsInvalidRecords(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	receipt := Receipt{
		Version:       Version,
		AttemptID:     admitted.AttemptID,
		TerminalKind:  "observation",
		AdmittedFile:  admittedFile,
		AdmittedHash:  strings.Repeat("a", 64),
		TerminalFile:  observationFile,
		TerminalHash:  strings.Repeat("b", 64),
		TerminalState: "verified",
	}
	for name, mutate := range map[string]func(*Admitted, *Receipt){
		"admitted": func(admitted *Admitted, _ *Receipt) {
			admitted.AdmittedAt = "invalid"
		},
		"receipt": func(_ *Admitted, receipt *Receipt) {
			receipt.Version++
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateAdmitted := admitted
			candidateReceipt := receipt
			mutate(&candidateAdmitted, &candidateReceipt)
			if err := validateReceipt(
				admitted.AttemptID,
				candidateAdmitted,
				candidateReceipt,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid %s accepted: %v", name, err)
			}
		})
	}
}

func TestAdmittedTimestampBindings(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	valid := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	for name, value := range map[string]string{
		"invalid":       "invalid",
		"non-UTC":       admittedAt.Add(time.Hour).Format("2006-01-02T15:04:05.999999999+01:00"),
		"non-canonical": strings.TrimSuffix(valid.AdmittedAt, "Z") + ".000Z",
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			record.AdmittedAt = value
			if err := validateAdmitted(record); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("timestamp %q accepted: %v", value, err)
			}
		})
	}
}

func TestRetainedVerificationRejectsMissingBindings(t *testing.T) {
	output := "output"
	response := completedResponse(output)
	valid := Observation{
		VerificationID:   URLVerifierID,
		VerificationVer:  URLVerifierVersion,
		ExpectedOutput:   output,
		VerificationPass: true,
	}
	for name, mutate := range map[string]func(*Observation){
		"identity": func(record *Observation) { record.VerificationID = "" },
		"version":  func(record *Observation) { record.VerificationVer = "" },
		"output":   func(record *Observation) { record.ExpectedOutput = "" },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if err := validateRetainedVerificationEvidence(
				workerRequest(),
				response,
				record,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("missing %s binding accepted: %v", name, err)
			}
		})
	}
}

func TestTimedOutStartFailureRejectsProcessEvidence(t *testing.T) {
	valid := failedRecord(t)
	valid.TerminalStatus = "timed_out"
	valid.ProcessStatus = "start_failed"
	valid.CleanupComplete = true
	for name, mutate := range map[string]func(*Observation){
		"exit code": func(record *Observation) { record.ExitCode = 1 },
		"stdout":    func(record *Observation) { record.Stdout = []byte("output") },
		"stderr":    func(record *Observation) { record.Stderr = []byte("error") },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if err := validateObservation(record); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("start failure with %s accepted: %v", name, err)
			}
		})
	}
}

func TestUnverifiedObservationRequiresCompleteBindings(t *testing.T) {
	accepted, _ := testAccepted(t)
	valid := testObservationFor(t, accepted)
	valid.TerminalStatus = "executed_unverified"
	valid.VerificationPass = false
	for name, mutate := range map[string]func(*Observation){
		"process status":    func(record *Observation) { record.ProcessStatus = "exit_failed" },
		"process error":     func(record *Observation) { record.ProcessError = "failed" },
		"exit code":         func(record *Observation) { record.ExitCode = 1 },
		"cleanup":           func(record *Observation) { record.CleanupComplete = false },
		"protocol":          func(record *Observation) { record.ProtocolStatus = "rejected" },
		"verifier identity": func(record *Observation) { record.VerificationID = "" },
		"verifier version":  func(record *Observation) { record.VerificationVer = "" },
		"expected output":   func(record *Observation) { record.ExpectedOutput = "" },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if err := validateObservation(record); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("unverified observation without %s accepted: %v", name, err)
			}
		})
	}
}

func TestCleanupFailureRequiresProcessFailure(t *testing.T) {
	valid := failedRecord(t)
	valid.ProcessStatus = "cleanup_failed"
	valid.CleanupComplete = false
	for name, mutate := range map[string]func(*Observation){
		"protocol": func(record *Observation) { record.ProtocolStatus = "valid" },
		"error":    func(record *Observation) { record.ProcessError = "" },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if err := validateObservation(record); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("cleanup failure without %s accepted: %v", name, err)
			}
		})
	}
}

func TestRecordHeadersRejectEarlyMismatches(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := testObservation(accepted.Request.AttemptID)
	observation.Version++
	if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("observation version accepted: %v", err)
	}
	receipt := Receipt{Version: Version + 1}
	if err := validateReceiptShape(receipt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("receipt version accepted: %v", err)
	}
	for name, publication := range map[string]Publication{
		"version": {
			Version:     Version + 1,
			AttemptID:   accepted.Request.AttemptID,
			ReceiptHash: strings.Repeat("a", 64),
		},
		"identity": {
			Version:     Version,
			AttemptID:   "invalid",
			ReceiptHash: strings.Repeat("a", 64),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePublication(publication); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("publication %s accepted: %v", name, err)
			}
		})
	}
}

func TestRetainedRequestRejectsFrameBounds(t *testing.T) {
	_, admittedAt := testAccepted(t)
	for name, frame := range map[string][]byte{
		"empty":         nil,
		"oversized":     bytes.Repeat([]byte{'x'}, requestV1FrameMax+1),
		"invalid UTF-8": {0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s frame accepted: %v", name, err)
			}
		})
	}
}

func TestRetainedRequestRejectsInvalidLimitsObject(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(accepted.Frame, &fields); err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	fields["limits"] = json.RawMessage(`"invalid"`)
	frame, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-object limits accepted: %v", err)
	}
}

func TestRetainedRequestRejectsMissingObjectToken(t *testing.T) {
	if _, ok := objectFieldsV1(nil); ok {
		t.Fatal("empty object accepted")
	}
}

func TestRetainedRequestConstants(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	valid := mustDecodeRequestV1(t, accepted.Frame, admittedAt)
	for name, mutate := range map[string]func(*requestV1){
		"protocol version":  func(request *requestV1) { request.ProtocolVersion++ },
		"operation":         func(request *requestV1) { request.OperationID = "different" },
		"operation version": func(request *requestV1) { request.OperationVersion++ },
		"media type":        func(request *requestV1) { request.InputMediaType = "application/json" },
		"timeout":           func(request *requestV1) { request.TimeoutMS++ },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			assertRequestV1Rejected(t, request, admittedAt)
		})
	}
}

func TestRetainedRequestModes(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	request := mustDecodeRequestV1(t, accepted.Frame, admittedAt)
	request.Mode = "fang"
	if !validRequestV1(request, admittedAt) {
		t.Fatal("fang mode rejected")
	}
}

func TestRetainedRequestCorrelationBindings(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	valid := mustDecodeRequestV1(t, accepted.Frame, admittedAt)
	for name, mutate := range map[string]func(*requestV1){
		"attempt": func(request *requestV1) { request.AttemptID = "invalid" },
		"nonce":   func(request *requestV1) { request.RequestNonce = "invalid" },
		"equal":   func(request *requestV1) { request.RequestNonce = request.AttemptID },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			assertRequestV1Rejected(t, request, admittedAt)
		})
	}
	for name, value := range map[string]string{
		"decode": "!",
		"length": "YQ",
	} {
		t.Run(name, func(t *testing.T) {
			if validIdentityV1(value) {
				t.Fatalf("%s identity accepted", name)
			}
		})
	}
}

func TestRetainedRequestInputBounds(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	valid := mustDecodeRequestV1(t, accepted.Frame, admittedAt)
	for name, value := range map[string]string{
		"invalid UTF-8": string([]byte{0xff}),
		"empty":         "",
		"oversized":     strings.Repeat("x", requestV1InputMax+1),
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			request.Input = value
			request.InputLength = len(value)
			hash := sha256.Sum256([]byte(value))
			request.InputSHA256 = hex.EncodeToString(hash[:])
			if validRequestV1Input(request) {
				t.Fatalf("%s input accepted", name)
			}
			if validRequestV1(request, admittedAt) {
				t.Fatalf("request with %s input accepted", name)
			}
		})
	}
}

func TestRetainedRequestDeadlines(t *testing.T) {
	admittedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for name, value := range map[string]string{
		"invalid":       "invalid",
		"non-canonical": "2026-01-02T03:04:17.000Z",
		"unequal":       admittedAt.Add(13 * time.Second).Format(time.RFC3339Nano),
	} {
		t.Run(name, func(t *testing.T) {
			if validRequestV1Deadline(value, admittedAt) {
				t.Fatalf("%s deadline accepted", name)
			}
		})
	}
}

func TestRetainedRequestSurrogatePair(t *testing.T) {
	next, invalid := inspectEscapedRuneV1([]byte(`\ud83d\ude00`), 0)
	if next != 11 || invalid {
		t.Fatalf("paired surrogate = (%d, %t)", next, invalid)
	}
}

func TestLoadTerminalRejectsUnknownKind(t *testing.T) {
	records := Records{Receipt: Receipt{TerminalKind: "unknown"}}
	if err := loadTerminal(t.TempDir(), &records); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown terminal kind accepted: %v", err)
	}
}

func completedResponse(output string) workerprotocol.Response {
	return workerprotocol.Response{
		Status: workerprotocol.Completed,
		Output: &output,
	}
}

func workerRequest() workerprotocol.Request {
	return workerprotocol.Request{}
}

func failedRecord(t *testing.T) Observation {
	t.Helper()
	accepted, _ := testAccepted(t)
	record := testObservation(accepted.Request.AttemptID)
	record.ProcessError = "failed"
	record.ProtocolStatus = "not_run"
	record.VerificationID = ""
	record.VerificationVer = ""
	record.ExpectedOutput = ""
	record.VerificationPass = false
	record.TerminalStatus = "failed"
	record.Stdout = nil
	return record
}

func mustDecodeRequestV1(t *testing.T, frame []byte, admittedAt time.Time) requestV1 {
	t.Helper()
	request, err := decodeRequestV1(frame, admittedAt)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return request
}

func assertRequestV1Rejected(t *testing.T, request requestV1, admittedAt time.Time) {
	t.Helper()
	frame, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if _, err := decodeRequestV1(frame, admittedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid request accepted: %v", err)
	}
}
