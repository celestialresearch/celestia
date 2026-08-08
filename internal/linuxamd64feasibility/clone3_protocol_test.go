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

package linuxamd64feasibility

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestClone3BootstrapRequiresGateBeforeReady(t *testing.T) {
	gate := bytes.NewBuffer([]byte{clone3GateByte, clone3GateByte})
	prepared := false
	ready := preparationWriter{prepared: &prepared}
	if err := runClone3Bootstrap(gate, &ready, func() error { prepared = true; return nil }); err != nil {
		t.Fatalf("run bootstrap: %v", err)
	}
	if !prepared || gate.Len() != 0 || !bytes.Equal(ready.Bytes(), []byte{clone3ReadyByte}) {
		t.Fatalf("gate=%d ready=%q", gate.Len(), ready.Bytes())
	}
}

type preparationWriter struct {
	prepared *bool
	bytes.Buffer
}

func (writer *preparationWriter) Write(data []byte) (int, error) {
	if writer.prepared == nil || !*writer.prepared {
		return 0, errors.New("bootstrap reported ready before preparation")
	}
	return writer.Buffer.Write(data)
}

func TestClone3BootstrapRejectsPreparationFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("prepare")
	err := runClone3Bootstrap(bytes.NewBuffer([]byte{clone3GateByte}), &bytes.Buffer{}, func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("runClone3Bootstrap() error = %v", err)
	}
}

func TestClone3BootstrapRejectsProtocolFailures(t *testing.T) {
	t.Parallel()
	want := errors.New("write")
	tests := []struct {
		name    string
		gate    []byte
		ready   io.Writer
		prepare func() error
	}{
		{"missing preparation", []byte{clone3GateByte}, &bytes.Buffer{}, nil},
		{"missing first gate", nil, &bytes.Buffer{}, func() error { return nil }},
		{"wrong first gate", []byte{'x'}, &bytes.Buffer{}, func() error { return nil }},
		{"ready failure", []byte{clone3GateByte}, failingBootstrapWriter{want}, func() error { return nil }},
		{"short ready write", []byte{clone3GateByte}, failingBootstrapWriter{}, func() error { return nil }},
		{"missing second gate", []byte{clone3GateByte}, &bytes.Buffer{}, func() error { return nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := runClone3Bootstrap(bytes.NewReader(test.gate), test.ready, test.prepare); err == nil {
				t.Fatal("protocol failure accepted")
			}
		})
	}
}

type failingBootstrapWriter struct{ err error }

func (writer failingBootstrapWriter) Write([]byte) (int, error) {
	return 0, writer.err
}
