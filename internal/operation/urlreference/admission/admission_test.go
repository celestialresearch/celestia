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

package urladmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
)

func TestAdmit(t *testing.T) {
	t.Parallel()

	admittedAt := time.Date(2026, 7, 25, 10, 0, 0, 123, time.UTC)
	randomness := bytes.NewReader(append(
		bytes.Repeat([]byte{0x11}, identityBytes),
		bytes.Repeat([]byte{0x22}, identityBytes)...,
	))
	accepted, err := admit(
		"https://example.test/a.b",
		urlreference.Defang,
		admittedAt,
		randomness,
	)
	if err != nil {
		t.Fatalf("admit() error = %v", err)
	}

	expectedAttempt := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	expectedNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	inputHash := sha256.Sum256([]byte("https://example.test/a.b"))
	if accepted.Request.AttemptID != expectedAttempt {
		t.Fatalf("attempt ID = %q, want %q", accepted.Request.AttemptID, expectedAttempt)
	}
	if accepted.Request.RequestNonce != expectedNonce {
		t.Fatalf("nonce = %q, want %q", accepted.Request.RequestNonce, expectedNonce)
	}
	if accepted.Request.InputSHA256 != hex.EncodeToString(inputHash[:]) {
		t.Fatalf("input hash = %q", accepted.Request.InputSHA256)
	}
	if accepted.Request.Deadline != "2026-07-25T10:00:12.000000123Z" {
		t.Fatalf("deadline = %q", accepted.Request.Deadline)
	}
	decoded, err := workerprotocol.DecodeRequest(accepted.Frame, admittedAt)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	if decoded != accepted.Request {
		t.Fatal("encoded request changed fields")
	}
	if !accepted.Timings.AdmissionMeasured || !accepted.Timings.RequestMeasured {
		t.Fatalf("successful admission timings = %+v", accepted.Timings)
	}
}

func TestAdmitUsesSecureRandomness(t *testing.T) {
	t.Parallel()

	admittedAt := time.Unix(0, 0).UTC()
	first, err := Admit("https://example.test", urlreference.Defang, admittedAt)
	if err != nil {
		t.Fatalf("first Admit() error = %v", err)
	}
	second, err := Admit("https://example.test", urlreference.Defang, admittedAt)
	if err != nil {
		t.Fatalf("second Admit() error = %v", err)
	}
	if first.Request.AttemptID == second.Request.AttemptID ||
		first.Request.RequestNonce == second.Request.RequestNonce {
		t.Fatal("Admit() reused an identity or nonce")
	}
}

func TestAdmitRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode urlreference.Mode
		time time.Time
		url  string
	}{
		{"invalid URL", urlreference.Defang, time.Unix(0, 0).UTC(), "example.test"},
		{"invalid mode", "invalid", time.Unix(0, 0).UTC(), "https://example.test"},
		{
			"non-UTC time",
			urlreference.Defang,
			time.Unix(0, 0).In(time.FixedZone("test", 3600)),
			"https://example.test",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			accepted, err := admit(
				test.url,
				test.mode,
				test.time,
				bytes.NewReader(make([]byte, 64)),
			)
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("admit() error = %v, want ErrRejected", err)
			}
			assertAdmissionOnly(t, accepted.Timings)
		})
	}
}

func TestAdmitRandomFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		randomness io.Reader
		want       string
	}{
		{
			name:       "attempt",
			randomness: bytes.NewReader(nil),
			want:       "generate attempt identity",
		},
		{
			name: "nonce",
			randomness: io.LimitReader(
				bytes.NewReader(make([]byte, identityBytes)),
				identityBytes,
			),
			want: "generate request nonce",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			accepted, err := admit(
				"https://example.test",
				urlreference.Defang,
				time.Unix(0, 0).UTC(),
				test.randomness,
			)
			if err == nil || errors.Is(err, ErrRejected) ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("admit() error = %v, want %q generation failure",
					err, test.want)
			}
			assertAdmissionOnly(t, accepted.Timings)
		})
	}
}

func TestAdmitRejectsRepeatedIdentity(t *testing.T) {
	t.Parallel()

	accepted, err := admit(
		"https://example.test",
		urlreference.Defang,
		time.Unix(0, 0).UTC(),
		bytes.NewReader(bytes.Repeat([]byte{1}, identityBytes*2)),
	)
	if err == nil || errors.Is(err, ErrRejected) {
		t.Fatalf("admit() error = %v, want entropy failure", err)
	}
	assertAdmissionOnly(t, accepted.Timings)
}

func TestAdmitRejectsUnencodableDeadline(t *testing.T) {
	t.Parallel()

	accepted, err := admit(
		"https://example.test",
		urlreference.Defang,
		time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC),
		bytes.NewReader(append(
			bytes.Repeat([]byte{1}, identityBytes),
			bytes.Repeat([]byte{2}, identityBytes)...,
		)),
	)
	if err == nil || errors.Is(err, ErrRejected) ||
		!strings.Contains(err.Error(), "encode admitted request") {
		t.Fatalf("admit() error = %v, want request encoding failure", err)
	}
	if !accepted.Timings.AdmissionMeasured || !accepted.Timings.RequestMeasured {
		t.Fatalf("request failure timings = %+v", accepted.Timings)
	}
}

func assertAdmissionOnly(t *testing.T, timings Timings) {
	t.Helper()
	if !timings.AdmissionMeasured || timings.RequestMeasured {
		t.Fatalf("admission-only timings = %+v", timings)
	}
}
