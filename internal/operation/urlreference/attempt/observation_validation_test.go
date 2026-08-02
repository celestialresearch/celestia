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
	"errors"
	"testing"

	workerprotocol "celestia.research/celestia/internal/operation/urlreference/protocol"
)

func TestObservationEvidenceRejectsContradictions(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	valid := testObservationFor(t, accepted)

	for name, mutate := range map[string]func(*Observation){
		"stdout overflow": func(value *Observation) {
			value.Stdout = bytes.Repeat(
				[]byte{'x'},
				workerprotocol.MaxResponseBytes+1,
			)
		},
		"stderr overflow": func(value *Observation) {
			value.Stderr = bytes.Repeat(
				[]byte{'x'},
				workerprotocol.StderrBytes+1,
			)
		},
		"valid malformed response": func(value *Observation) {
			value.Stdout = []byte("{")
		},
		"rejected valid response": func(value *Observation) {
			value.ProtocolStatus = "rejected"
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation := valid
			mutate(&observation)
			if err := validateObservationEvidence(
				admitted,
				observation,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("contradictory evidence accepted: %v", err)
			}
		})
	}

	notRun := valid
	notRun.ProtocolStatus = "not_run"
	if err := validateObservationEvidence(admitted, notRun); err != nil {
		t.Fatalf("not-run protocol evidence rejected: %v", err)
	}
	rejected := valid
	rejected.ProtocolStatus = "rejected"
	rejected.Stdout = []byte("{")
	if err := validateObservationEvidence(admitted, rejected); err != nil {
		t.Fatalf("rejected protocol evidence rejected: %v", err)
	}
}

func TestRetainedVerificationBindings(t *testing.T) {
	output := "output"
	failed := workerprotocol.Response{Status: workerprotocol.Failed}
	if err := validateRetainedVerificationEvidence(
		workerprotocol.Request{},
		failed,
		Observation{},
	); err != nil {
		t.Fatalf("failed response required verification: %v", err)
	}

	completed := workerprotocol.Response{
		Status: workerprotocol.Completed,
		Output: &output,
	}
	valid := Observation{
		VerificationID:   URLVerifierID,
		VerificationVer:  URLVerifierVersion,
		ExpectedOutput:   output,
		VerificationPass: true,
	}
	if err := validateRetainedVerificationEvidence(
		workerprotocol.Request{},
		completed,
		valid,
	); err != nil {
		t.Fatalf("valid retained verification rejected: %v", err)
	}
	valid.ExpectedOutput = "different"
	if err := validateRetainedVerificationEvidence(
		workerprotocol.Request{},
		completed,
		valid,
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("contradictory retained verification accepted: %v", err)
	}
}

func TestDecodeObservationEvidenceRejectsInvalidAdmission(t *testing.T) {
	accepted, admittedAt := testAccepted(t)
	admitted := admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	observation := testObservationFor(t, accepted)

	admitted.AdmittedAt = "invalid"
	if _, _, err := decodeObservationEvidence(
		admitted,
		observation,
	); err == nil {
		t.Fatal("invalid admitted timestamp accepted")
	}
	admitted = admittedRecord(accepted.Request, accepted.Frame, admittedAt)
	admitted.RequestFrame = []byte("{")
	if _, _, err := decodeObservationEvidence(
		admitted,
		observation,
	); err == nil {
		t.Fatal("invalid admitted request accepted")
	}
}

func TestVerificationEvidenceRejectsInvalidTransformation(t *testing.T) {
	response := workerprotocol.Response{Status: workerprotocol.Failed}
	if err := validateVerificationEvidence(
		workerprotocol.Request{},
		response,
		Observation{},
	); err != nil {
		t.Fatalf("failed response required verification: %v", err)
	}

	output := "output"
	response = workerprotocol.Response{
		Status: workerprotocol.Completed,
		Output: &output,
	}
	request := workerprotocol.Request{Mode: "invalid"}
	if err := validateVerificationEvidence(
		request,
		response,
		Observation{},
	); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid transformation accepted: %v", err)
	}
}
