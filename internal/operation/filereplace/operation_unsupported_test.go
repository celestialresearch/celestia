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
	"errors"
	"testing"
)

func TestUnsupportedPlatformRefusesConstruction(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New() error = %v", err)
	}
}
