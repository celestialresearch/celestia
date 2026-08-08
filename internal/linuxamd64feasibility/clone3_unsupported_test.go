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
	"os/exec"
	"testing"
)

func TestClone3CgroupPrimitiveRefusesUnsupportedPlatform(t *testing.T) {
	result := clone3CgroupPrimitive("ignored", exec.CommandContext(t.Context(), "ignored"), nil)
	if result != unavailableCgroup("linux_amd64_required") {
		t.Fatalf("result=%+v", result)
	}
}
