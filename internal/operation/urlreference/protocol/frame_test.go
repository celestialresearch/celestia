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
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestJSONFrameDepthLimit(t *testing.T) {
	t.Parallel()

	within := strings.Repeat("[", MaxJSONDepth) + "0" + strings.Repeat("]", MaxJSONDepth)
	if err := validateJSONFrame([]byte(within)); err != nil {
		t.Fatalf("bounded JSON nesting rejected: %v", err)
	}
	excessive := "[" + within + "]"
	if err := validateJSONFrame([]byte(excessive)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("excessive JSON nesting accepted: %v", err)
	}
}
func TestHasUnpairedSurrogate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		data   string
		paired bool
	}{
		{"high", `{"value":"\ud800"}`, false},
		{"low", `{"value":"\udc00"}`, false},
		{"wrong pair", `{"value":"\ud800\u0041"}`, false},
		{"pair", `{"value":"\ud83d\ude00"}`, true},
		{"escaped text", `{"value":"\\ud800"}`, true},
		{"escaped quote then high", `{"value":"\"\ud800"}`, false},
		{"escaped quote then low", `{"value":"\"\udc00"}`, false},
		{"escaped quote then pair", `{"value":"\"\ud83d\ude00"}`, true},
		{"escaped slash then high", `{"value":"\\\ud800"}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := !hasUnpairedSurrogate([]byte(test.data)); got != test.paired {
				t.Fatalf("paired = %t, want %t", got, test.paired)
			}
		})
	}
}
func TestInspectEscapedRune(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    string
		index   int
		next    int
		invalid bool
	}{
		{"ordinary escape", `\n`, 0, 1, false},
		{"non-surrogate", `\u1234`, 0, 5, false},
		{"invalid hex", `\u12x4`, 0, 5, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			next, invalid := inspectEscapedRune([]byte(test.data), test.index)
			if next != test.next || invalid != test.invalid {
				t.Fatalf(
					"inspectEscapedRune() = (%d, %t), want (%d, %t)",
					next,
					invalid,
					test.next,
					test.invalid,
				)
			}
		})
	}
}
func TestDecodeHex4(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		data  string
		value uint16
		ok    bool
	}{
		{"wrong length", "123", 0, false},
		{"decimal", "1234", 0x1234, true},
		{"lowercase", "abcf", 0xabcf, true},
		{"uppercase", "ABCF", 0xabcf, true},
		{"invalid", "12x4", 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value, ok := decodeHex4([]byte(test.data))
			if value != test.value || ok != test.ok {
				t.Fatalf(
					"decodeHex4(%q) = (%#x, %t), want (%#x, %t)",
					test.data,
					value,
					ok,
					test.value,
					test.ok,
				)
			}
		})
	}
}
func TestValidateRawDiagnosticsRejects(t *testing.T) {
	t.Parallel()

	if err := validateRawDiagnostics([]byte(`[`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}
func TestRawRequestFieldsRejectMalformed(t *testing.T) {
	t.Parallel()

	if err := validateRequestFields([]byte(`{`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("request fields error = %v, want ErrProtocol", err)
	}
	if err := validateLimitFields([]byte(`{`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("limits fields error = %v, want ErrProtocol", err)
	}
}
func TestValidateFieldsRejects(t *testing.T) {
	t.Parallel()

	if err := validateFields([]byte(`{`), Completed); !errors.Is(err, ErrProtocol) {
		t.Fatalf("malformed error = %v, want ErrProtocol", err)
	}
	data := []byte(`{"protocol_version":1,"operation_id":"url-reference","operation_version":1,"attempt_id":"attempt","request_nonce":"nonce","worker_id":"celestia-url-reference","worker_version":"1","status":"failed","unknown":[],"duration_ns":0}`)
	if err := validateFields(data, Failed); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing field error = %v, want ErrProtocol", err)
	}
}
func TestProtocolScannerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func() error
	}{
		{"missing value", func() error { return scanValue(json.NewDecoder(bytes.NewBuffer(nil)), 0) }},
		{"unexpected delimiter", unexpectedDelimiter},
		{"missing object key", func() error { return scanObject(json.NewDecoder(bytes.NewBuffer(nil)), 0) }},
		{"non-string object key", func() error { return scanObject(json.NewDecoder(bytes.NewBufferString(`1`)), 0) }},
		{"invalid object key", invalidObjectKey},
		{"invalid object value", invalidObjectValue},
		{"invalid array value", func() error { return scanArray(json.NewDecoder(bytes.NewBufferString(`{`)), 0) }},
		{"missing delimiter", func() error { return expectDelimiter(json.NewDecoder(bytes.NewBuffer(nil)), '}') }},
		{"wrong delimiter", wrongDelimiter},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.run(); !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want ErrProtocol", err)
			}
		})
	}
}
func unexpectedDelimiter() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`[]`))
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return scanValue(decoder, 0)
}
func invalidObjectKey() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`[tru`))
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return scanObject(decoder, 0)
}
func invalidObjectValue() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`{"a"`))
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return scanObject(decoder, 0)
}
func wrongDelimiter() error {
	decoder := json.NewDecoder(bytes.NewBufferString(`[]`))
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return expectDelimiter(decoder, '}')
}
