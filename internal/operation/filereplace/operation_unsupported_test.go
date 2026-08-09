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

//go:build !windows || !amd64

package filereplace

import (
	"context"
	"errors"
	"testing"

	"celestia.research/celestia/internal/operation/filereplace/admission"
)

func TestUnsupportedPlatformRefusesConstruction(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New() error = %v", err)
	}
}

func TestUnsupportedPlatformRefusesOperations(t *testing.T) {
	t.Parallel()

	operation := &Operation{}
	if _, err := operation.Execute(context.Background(), admission.Request{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Execute() error = %v", err)
	}
	if _, err := operation.Recover(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := operation.Inspect("attempt"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Inspect() error = %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNilOperationRefusesCalls(t *testing.T) {
	t.Parallel()

	var operation *Operation
	if _, err := operation.Execute(context.Background(), admission.Request{}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Execute() error = %v", err)
	}
	if _, err := operation.Recover(context.Background()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := operation.Inspect("attempt"); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Inspect() error = %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
