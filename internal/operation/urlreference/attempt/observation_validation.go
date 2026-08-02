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
	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"time"
)

func validateObservation(record Observation) error {
	if record.Version != Version ||
		!validIdentity(record.AttemptID) ||
		!validHash(record.WorkerSHA256) ||
		!validProcessStatus(record.ProcessStatus) ||
		!validProtocolStatus(record.ProtocolStatus) ||
		record.DurationNS < 0 {
		return ErrCorrupt
	}
	return validateObservationTransition(record)
}

func validateObservationEvidence(admitted Admitted, observation Observation) error {
	return validateObservationEvidenceWith(admitted, observation, validateVerificationEvidence)
}

func validateRetainedObservationEvidence(admitted Admitted, observation Observation) error {
	return validateObservationEvidenceWith(
		admitted,
		observation,
		validateRetainedVerificationEvidence,
	)
}

func validateObservationEvidenceWith(
	admitted Admitted,
	observation Observation,
	validateVerification func(workerprotocol.Request, workerprotocol.Response, Observation) error,
) error {
	if len(observation.Stdout) > workerprotocol.MaxResponseBytes ||
		len(observation.Stderr) > workerprotocol.StderrBytes {
		return ErrCorrupt
	}
	if observation.ProtocolStatus == "not_run" {
		return nil
	}
	request, response, responseErr := decodeObservationEvidence(admitted, observation)
	switch observation.ProtocolStatus {
	case "valid":
		if responseErr != nil {
			return ErrCorrupt
		}
		return validateVerification(request, response, observation)
	case "rejected":
		if responseErr == nil {
			return ErrCorrupt
		}
	}
	return nil
}

func validateRetainedVerificationEvidence(
	_ workerprotocol.Request,
	response workerprotocol.Response,
	observation Observation,
) error {
	if response.Status != workerprotocol.Completed {
		return nil
	}
	if observation.VerificationID != URLVerifierID ||
		observation.VerificationVer != URLVerifierVersion ||
		observation.ExpectedOutput == "" ||
		observation.VerificationPass != (*response.Output == observation.ExpectedOutput) {
		return ErrCorrupt
	}
	return nil
}

func decodeObservationEvidence(
	admitted Admitted,
	observation Observation,
) (workerprotocol.Request, workerprotocol.Response, error) {
	admittedAt, err := time.Parse(time.RFC3339Nano, admitted.AdmittedAt)
	if err != nil {
		return workerprotocol.Request{}, workerprotocol.Response{}, err
	}
	retained, err := decodeRequestV1(admitted.RequestFrame, admittedAt)
	if err != nil {
		return workerprotocol.Request{}, workerprotocol.Response{}, err
	}
	request := retained.workerRequest()
	response, err := workerprotocol.DecodeResponseForRequestCorrelation(
		observation.Stdout,
		request,
		int(observation.ExitCode),
	)
	return request, response, err
}

func validateVerificationEvidence(
	request workerprotocol.Request,
	response workerprotocol.Response,
	observation Observation,
) error {
	if response.Status != workerprotocol.Completed {
		return nil
	}
	expected, err := urlreference.Transform(
		request.Input,
		urlreference.Mode(request.Mode),
	)
	if err != nil ||
		observation.VerificationID != URLVerifierID ||
		observation.VerificationVer != URLVerifierVersion ||
		observation.ExpectedOutput != expected ||
		observation.VerificationPass != (*response.Output == expected) {
		return ErrCorrupt
	}
	return nil
}
