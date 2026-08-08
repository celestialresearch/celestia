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

//go:build windows || (linux && amd64)

package attemptstore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func FuzzDecodeRecord(f *testing.F) {
	accepted, admittedAt := testAccepted(f)
	hash := strings.Repeat("0", 64)
	records := []any{
		Admitted{
			Version:       Version,
			AttemptID:     accepted.Request.AttemptID,
			AdmittedAt:    admittedAt.Format(time.RFC3339Nano),
			OriginalInput: accepted.Request.Input,
			RequestFrame:  accepted.Frame,
		},
		testObservationFor(f, accepted),
		Receipt{
			Version:       Version,
			AttemptID:     accepted.Request.AttemptID,
			TerminalKind:  "observation",
			AdmittedFile:  admittedFile,
			AdmittedHash:  hash,
			TerminalFile:  observationFile,
			TerminalHash:  hash,
			TerminalState: "verified",
		},
		Publication{
			Version:     Version,
			AttemptID:   accepted.Request.AttemptID,
			ReceiptHash: hash,
		},
	}
	for kind, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			f.Fatalf("encode seed record: %v", err)
		}
		f.Add(uint8(kind), data)
	}
	recovery, err := json.Marshal(Recovery{
		Version:        Version,
		AttemptID:      accepted.Request.AttemptID,
		TerminalStatus: "indeterminate",
		Reason:         "interrupted before terminal publication",
	})
	if err != nil {
		f.Fatalf("encode recovery seed: %v", err)
	}
	f.Add(uint8(4), recovery)
	f.Add(uint8(0), []byte(nil))

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > maxRecordBytes {
			return
		}
		target := recordTarget(kind)
		if err := decodeRecord(data, target); err != nil {
			return
		}
		encoded, err := json.Marshal(target)
		if err != nil {
			t.Fatalf("marshal accepted record: %v", err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatal("accepted record is not canonical")
		}
		second := recordTarget(kind)
		if err := decodeRecord(data, second); err != nil {
			t.Fatalf("accepted record was rejected on replay: %v", err)
		}
		if !reflect.DeepEqual(target, second) {
			t.Fatal("record decoding is nondeterministic")
		}
	})
}

func recordTarget(kind uint8) any {
	switch kind % 5 {
	case 0:
		return &Admitted{}
	case 1:
		return &Observation{}
	case 2:
		return &Receipt{}
	case 3:
		return &Publication{}
	default:
		return &Recovery{}
	}
}
