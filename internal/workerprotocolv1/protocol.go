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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"celestia.research/governed-operation/internal/urlreferencev1"
)

const (
	ProtocolVersion  = 1
	OperationID      = "url-reference"
	OperationVersion = 1
	WorkerID         = "celestia-url-reference"
	WorkerVersion    = "1"
	MediaType        = "text/plain; charset=utf-8"
	MaxResponseBytes = 65536
	MaxOutputBytes   = 8192
	MaxDiagnostics   = 16
	MaxMessageBytes  = 512
	MaxDurationNS    = 2_000_000_000
	MaxJSONDepth     = 32
	InputBytes       = 4096
	StderrBytes      = 8192
	MemoryBytes      = 67108864
	Processes        = 1
	StartTimeoutMS   = 12000
	TimeoutMS        = 2000
)

var (
	ErrProtocol    = errors.New("invalid worker protocol")
	diagnosticCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	decimalInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	lowerHex       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Request struct {
	ProtocolVersion  int    `json:"protocol_version"`
	OperationID      string `json:"operation_id"`
	OperationVersion int    `json:"operation_version"`
	AttemptID        string `json:"attempt_id"`
	RequestNonce     string `json:"request_nonce"`
	InputMediaType   string `json:"input_media_type"`
	InputLength      int    `json:"input_length"`
	InputSHA256      string `json:"input_sha256"`
	Mode             string `json:"mode"`
	Deadline         string `json:"deadline"`
	TimeoutMS        int    `json:"timeout_ms"`
	Limits           Limits `json:"limits"`
	Input            string `json:"input"`
}

type Limits struct {
	InputBytes  int `json:"input_bytes"`
	OutputBytes int `json:"output_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	MemoryBytes int `json:"memory_bytes"`
	Processes   int `json:"processes"`
}

type Response struct {
	ProtocolVersion  int          `json:"protocol_version"`
	OperationID      string       `json:"operation_id"`
	OperationVersion int          `json:"operation_version"`
	AttemptID        string       `json:"attempt_id"`
	RequestNonce     string       `json:"request_nonce"`
	WorkerID         string       `json:"worker_id"`
	WorkerVersion    string       `json:"worker_version"`
	Status           Status       `json:"status"`
	OutputMediaType  *string      `json:"output_media_type,omitempty"`
	OutputLength     *int         `json:"output_length,omitempty"`
	OutputSHA256     *string      `json:"output_sha256,omitempty"`
	Output           *string      `json:"output,omitempty"`
	Diagnostics      []Diagnostic `json:"diagnostics"`
	DurationNS       int64        `json:"duration_ns"`
}

type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Status string

const (
	Completed Status = "completed"
	Rejected  Status = "rejected"
	Failed    Status = "failed"
)

type Correlation struct {
	attemptID string
	nonce     string
	mediaType string
}

func DecodeResponse(data []byte, correlation Correlation, exitCode int) (Response, error) {
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
	return DecodeResponse(data, correlationFor(request), exitCode)
}

func EncodeRequest(request Request, admittedAt time.Time) ([]byte, Correlation, error) {
	correlation, err := ValidateRequest(request, admittedAt)
	if err != nil {
		return nil, Correlation{}, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, Correlation{}, protocolError("encode request")
	}
	return data, correlation, nil
}

func DecodeRequest(data []byte, admittedAt time.Time) (Request, Correlation, error) {
	if len(data) == 0 || len(data) > MaxResponseBytes || !utf8.Valid(data) {
		return Request{}, Correlation{}, protocolError("request bounds or UTF-8")
	}
	if err := validateJSONFrame(data); err != nil {
		return Request{}, Correlation{}, err
	}
	if err := validateRequestFields(data); err != nil {
		return Request{}, Correlation{}, err
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, Correlation{}, protocolError("decode request")
	}
	correlation, err := ValidateRequest(request, admittedAt)
	if err != nil {
		return Request{}, Correlation{}, err
	}
	return request, correlation, nil
}

func ValidateRequest(request Request, admittedAt time.Time) (Correlation, error) {
	if err := validateRequestConstants(request); err != nil {
		return Correlation{}, err
	}
	if !validIdentity(request.AttemptID) ||
		!validIdentity(request.RequestNonce) ||
		request.AttemptID == request.RequestNonce {
		return Correlation{}, protocolError("request identity")
	}
	if request.Mode != "fang" && request.Mode != "defang" {
		return Correlation{}, protocolError("request mode")
	}
	if err := validateRequestInput(request); err != nil {
		return Correlation{}, err
	}
	if err := validateDeadline(request.Deadline, admittedAt); err != nil {
		return Correlation{}, err
	}
	if request.Limits != (Limits{
		InputBytes:  InputBytes,
		OutputBytes: MaxOutputBytes,
		StderrBytes: StderrBytes,
		MemoryBytes: MemoryBytes,
		Processes:   Processes,
	}) {
		return Correlation{}, protocolError("request limits")
	}
	return correlationFor(request), nil
}

func correlationFor(request Request) Correlation {
	return Correlation{
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
	if !utf8.ValidString(request.Input) ||
		len(request.Input) < 1 ||
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

func validateRequestFields(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocolError("request field set")
	}
	required := []string{
		"protocol_version",
		"operation_id",
		"operation_version",
		"attempt_id",
		"request_nonce",
		"input_media_type",
		"input_length",
		"input_sha256",
		"mode",
		"deadline",
		"timeout_ms",
		"limits",
		"input",
	}
	if err := requireFields(fields, required); err != nil {
		return err
	}
	for _, name := range []string{"protocol_version", "operation_version", "input_length", "timeout_ms"} {
		if !decimalInteger.Match(fields[name]) {
			return protocolError("request integer field")
		}
	}
	for _, name := range []string{
		"operation_id",
		"attempt_id",
		"request_nonce",
		"input_media_type",
		"input_sha256",
		"mode",
		"deadline",
		"input",
	} {
		if !rawString(fields[name]) {
			return protocolError("request string field")
		}
	}
	return validateLimitFields(fields["limits"])
}

func validateLimitFields(data json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocolError("limits field")
	}
	required := []string{"input_bytes", "output_bytes", "stderr_bytes", "memory_bytes", "processes"}
	if err := requireFields(fields, required); err != nil {
		return err
	}
	for _, name := range required {
		if !decimalInteger.Match(fields[name]) {
			return protocolError("limit integer field")
		}
	}
	return nil
}

func requireFields(fields map[string]json.RawMessage, required []string) error {
	if len(fields) != len(required) {
		return protocolError("field set")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return protocolError("missing field")
		}
	}
	return nil
}

func validateFields(data []byte, status Status) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocolError("field set")
	}
	required := []string{
		"protocol_version",
		"operation_id",
		"operation_version",
		"attempt_id",
		"request_nonce",
		"worker_id",
		"worker_version",
		"status",
		"diagnostics",
		"duration_ns",
	}
	if status == Completed {
		required = append(required,
			"output_media_type",
			"output_length",
			"output_sha256",
			"output",
		)
	}
	if err := requireFields(fields, required); err != nil {
		return err
	}
	if diagnostics := fields["diagnostics"]; len(diagnostics) == 0 || diagnostics[0] != '[' {
		return protocolError("diagnostics type")
	}
	return validateRawFields(fields, status)
}

func validateRawFields(fields map[string]json.RawMessage, status Status) error {
	for _, name := range []string{"protocol_version", "operation_version", "duration_ns"} {
		if !decimalInteger.Match(fields[name]) {
			return protocolError("integer field")
		}
	}
	for _, name := range []string{
		"operation_id",
		"attempt_id",
		"request_nonce",
		"worker_id",
		"worker_version",
		"status",
	} {
		if !rawString(fields[name]) {
			return protocolError("string field")
		}
	}
	if status == Completed {
		if !decimalInteger.Match(fields["output_length"]) {
			return protocolError("output length type")
		}
		for _, name := range []string{"output_media_type", "output_sha256", "output"} {
			if !rawString(fields[name]) {
				return protocolError("output string type")
			}
		}
	}
	return validateRawDiagnostics(fields["diagnostics"])
}

func validateRawDiagnostics(data json.RawMessage) error {
	var diagnostics []map[string]json.RawMessage
	if err := json.Unmarshal(data, &diagnostics); err != nil {
		return protocolError("diagnostics decode")
	}
	for _, diagnostic := range diagnostics {
		if len(diagnostic) != 2 ||
			!rawString(diagnostic["code"]) ||
			!rawString(diagnostic["message"]) {
			return protocolError("diagnostic fields")
		}
	}
	return nil
}

func rawString(data json.RawMessage) bool {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(data, &value) == nil
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

func validateJSONFrame(data []byte) error {
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil || !bytes.Equal(compact.Bytes(), data) {
		return protocolError("frame")
	}
	if hasUnpairedSurrogate(data) {
		return protocolError("unpaired surrogate")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanValue(decoder, 0); err != nil {
		return err
	}
	return nil
}

func hasUnpairedSurrogate(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[index] != '\\' {
			continue
		}
		next, invalid := inspectEscapedRune(data, index)
		if invalid {
			return true
		}
		index = next
	}
	return false
}

func inspectEscapedRune(data []byte, index int) (int, bool) {
	if index+5 >= len(data) || data[index+1] != 'u' {
		return min(index+1, len(data)-1), false
	}
	value, ok := decodeHex4(data[index+2 : index+6])
	if !ok || value&0xf800 != 0xd800 {
		return index + 5, false
	}
	if value&0xfc00 == 0xdc00 {
		return index + 5, true
	}
	if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
		return index + 5, true
	}
	low, ok := decodeHex4(data[index+8 : index+12])
	if !ok || low&0xfc00 != 0xdc00 {
		return index + 5, true
	}
	return index + 11, false
}

func decodeHex4(data []byte) (uint16, bool) {
	if len(data) != 4 {
		return 0, false
	}
	var value uint16
	for _, digit := range data {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func scanValue(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONDepth {
		return protocolError("JSON nesting depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return protocolError("token")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return scanObject(decoder, depth)
	case '[':
		return scanArray(decoder, depth)
	default:
		return protocolError("unexpected delimiter")
	}
}

func scanObject(decoder *json.Decoder, depth int) error {
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return protocolError("object key")
		}
		key, ok := token.(string)
		if !ok {
			return protocolError("object key")
		}
		if _, duplicate := keys[key]; duplicate {
			return protocolError("duplicate field")
		}
		keys[key] = struct{}{}
		if err := scanValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return expectDelimiter(decoder, '}')
}

func scanArray(decoder *json.Decoder, depth int) error {
	for decoder.More() {
		if err := scanValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return expectDelimiter(decoder, ']')
}

func expectDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return protocolError("closing delimiter")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return protocolError("closing delimiter")
	}
	return nil
}

func protocolError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, arguments...))
}
