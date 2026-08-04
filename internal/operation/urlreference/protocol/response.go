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

package workerprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"
)

func decodeResponse(data []byte, correlation Correlation, exitCode int) (Response, error) {
	if len(data) == 0 || len(data) > MaxResponseBytes || !utf8.Valid(data) {
		return Response{}, protocolError("response bounds or UTF-8")
	}
	if err := validateJSONFrame(data); err != nil {
		return Response{}, err
	}
	var response Response
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return Response{}, protocolError("decode")
	}
	if err := validateFields(data, response.Status); err != nil {
		return Response{}, err
	}
	if err := validateResponse(response, correlation, exitCode); err != nil {
		return Response{}, err
	}
	return response, nil
}

func DecodeResponseForRequestCorrelation(
	data []byte,
	request Request,
	exitCode int,
) (Response, error) {
	if !validIdentity(request.AttemptID) ||
		!validIdentity(request.RequestNonce) ||
		request.AttemptID == request.RequestNonce ||
		request.InputMediaType != MediaType {
		return Response{}, protocolError("request correlation")
	}
	return decodeResponse(data, correlationFor(request), exitCode)
}

func validateResponse(response Response, correlation Correlation, exitCode int) error {
	if err := validateIdentity(response, correlation); err != nil {
		return err
	}
	if err := validateDiagnostics(response); err != nil {
		return err
	}
	return validateStatus(response, correlation, exitCode)
}

func validateIdentity(response Response, correlation Correlation) error {
	if response.ProtocolVersion != ProtocolVersion ||
		response.OperationID != OperationID ||
		response.OperationVersion != OperationVersion ||
		response.AttemptID != correlation.attemptID ||
		response.RequestNonce != correlation.nonce ||
		response.WorkerID != WorkerID ||
		response.WorkerVersion != WorkerVersion {
		return protocolError("identity or version mismatch")
	}
	if response.DurationNS < 0 || response.DurationNS > MaxDurationNS {
		return protocolError("duration")
	}
	return nil
}

func validateDiagnostics(response Response) error {
	if len(response.Diagnostics) > MaxDiagnostics {
		return protocolError("diagnostic count")
	}
	for _, diagnostic := range response.Diagnostics {
		if !diagnosticCode.MatchString(diagnostic.Code) ||
			!utf8.ValidString(diagnostic.Message) ||
			len(diagnostic.Message) > MaxMessageBytes {
			return protocolError("diagnostic")
		}
	}
	return nil
}

func validateStatus(response Response, correlation Correlation, exitCode int) error {
	switch response.Status {
	case Completed:
		if exitCode != 0 {
			return protocolError("completed exit")
		}
		return validateOutput(response, correlation)
	case Rejected:
		if exitCode != 2 || len(response.Diagnostics) == 0 {
			return protocolError("rejected response")
		}
	case Failed:
		if exitCode != 3 || len(response.Diagnostics) == 0 {
			return protocolError("failed response")
		}
	default:
		return protocolError("status")
	}
	return nil
}

func validateOutput(response Response, correlation Correlation) error {
	if *response.OutputMediaType != correlation.mediaType ||
		!utf8.ValidString(*response.Output) ||
		*response.OutputLength < 1 ||
		*response.OutputLength > MaxOutputBytes ||
		len(*response.Output) != *response.OutputLength {
		return protocolError("output metadata")
	}
	hash := sha256.Sum256([]byte(*response.Output))
	if !lowerHex.MatchString(*response.OutputSHA256) ||
		*response.OutputSHA256 != hex.EncodeToString(hash[:]) {
		return protocolError("output hash")
	}
	return nil
}
