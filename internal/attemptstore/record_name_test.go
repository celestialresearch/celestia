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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows

package attemptstore

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRecordTempNameSupportsRecovery(t *testing.T) {
	t.Parallel()

	name, err := recordTempName(admittedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !temporaryRecordName(admittedFile, name) {
		t.Fatalf("recordTempName() = %q is not recoverable", name)
	}
}

func TestRecordTempNameRejectsEntropyFailure(t *testing.T) {
	t.Parallel()

	for _, randomness := range []struct {
		name   string
		reader *bytes.Reader
		want   error
	}{
		{name: "empty", reader: bytes.NewReader(nil), want: io.EOF},
		{
			name:   "short",
			reader: bytes.NewReader(make([]byte, 15)),
			want:   io.ErrUnexpectedEOF,
		},
	} {
		t.Run(randomness.name, func(t *testing.T) {
			t.Parallel()
			if _, err := recordTempNameWith(
				admittedFile,
				randomness.reader,
			); !errors.Is(err, randomness.want) {
				t.Fatalf("entropy error=%v, want %v", err, randomness.want)
			}
		})
	}
}

func TestTemporaryRecordNameRejectsInvalidHex(t *testing.T) {
	for _, candidate := range []string{
		"." + admittedFile + "." + "0000000000000000000000000000000/",
		"." + admittedFile + "." + "0000000000000000000000000000000A",
		"." + admittedFile + "." + "gggggggggggggggggggggggggggggggg",
	} {
		if temporaryRecordName(admittedFile, candidate) {
			t.Fatalf("invalid temporary name accepted: %q", candidate)
		}
	}
}
