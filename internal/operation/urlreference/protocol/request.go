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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"celestia.research/celestia/internal/operation/urlreference/transform"
)

func EncodeRequest(request Request, admittedAt time.Time) ([]byte, error) {
	if err := validateRequest(request, admittedAt); err != nil {
		return nil, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, protocolError("encode request")
	}
	return data, nil
}

func DecodeRequest(data []byte, admittedAt time.Time) (Request, error) {
	if len(data) == 0 || len(data) > MaxResponseBytes || !utf8.Valid(data) {
		return Request{}, protocolError("request bounds or UTF-8")
	}
	if err := validateJSONFrame(data); err != nil {
		return Request{}, err
	}
	if err := validateRequestFields(data); err != nil {
		return Request{}, err
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, protocolError("decode request")
	}
	if err := validateRequest(request, admittedAt); err != nil {
		return Request{}, err
	}
	return request, nil
}

func validateRequest(request Request, admittedAt time.Time) error {
	if err := validateRequestConstants(request); err != nil {
		return err
	}
	if !validIdentity(request.AttemptID) ||
		!validIdentity(request.RequestNonce) ||
		request.AttemptID == request.RequestNonce {
		return protocolError("request identity")
	}
	if request.Mode != "fang" && request.Mode != "defang" {
		return protocolError("request mode")
	}
	if err := validateRequestInput(request); err != nil {
		return err
	}
	if err := validateDeadline(request.Deadline, admittedAt); err != nil {
		return err
	}
	if request.Limits != (Limits{
		InputBytes:  InputBytes,
		OutputBytes: MaxOutputBytes,
		StderrBytes: StderrBytes,
		MemoryBytes: MemoryBytes,
		Processes:   Processes,
	}) {
		return protocolError("request limits")
	}
	return nil
}

func correlationFor(request Request) responseCorrelation {
	return responseCorrelation{
		attemptID: request.AttemptID,
		nonce:     request.RequestNonce,
		mediaType: request.InputMediaType,
	}
}

func validateRequestConstants(request Request) error {
	if request.ProtocolVersion != ProtocolVersion ||
		request.OperationID != OperationID ||
		request.OperationVersion != OperationVersion ||
		request.InputMediaType != MediaType ||
		request.TimeoutMS != TimeoutMS {
		return protocolError("request constants")
	}
	return nil
}

func validateRequestInput(request Request) error {
	if len(request.Input) < 1 ||
		len(request.Input) > InputBytes ||
		request.InputLength != len(request.Input) {
		return protocolError("request input")
	}
	if err := urlreference.ValidateInput(request.Input); err != nil {
		return protocolError("request URL reference")
	}
	hash := sha256.Sum256([]byte(request.Input))
	if request.InputSHA256 != hex.EncodeToString(hash[:]) {
		return protocolError("request hash")
	}
	return nil
}

func validateDeadline(value string, admittedAt time.Time) error {
	if !strings.HasSuffix(value, "Z") {
		return protocolError("request deadline")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Format(time.RFC3339Nano) != value {
		return protocolError("request deadline")
	}
	expected := admittedAt.UTC().Add(
		time.Duration(StartTimeoutMS) * time.Millisecond,
	)
	if !parsed.Equal(expected) {
		return protocolError("request deadline")
	}
	return nil
}

func validIdentity(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil &&
		len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}
