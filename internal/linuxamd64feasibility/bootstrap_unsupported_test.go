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

//go:build !linux || !amd64

package linuxamd64feasibility

import (
	"errors"
	"testing"
)

func TestBootstrapRequiresLinuxAMD64(t *testing.T) {
	t.Parallel()

	if err := Bootstrap(nil, nil); !errors.Is(err, errBootstrapUnsupported) {
		t.Fatalf("Bootstrap() error = %v", err)
	}
}
