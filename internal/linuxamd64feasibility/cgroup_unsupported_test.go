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

import "testing"

func TestCgroupPrimitiveRequiresLinuxAMD64(t *testing.T) {
	if result := cgroupPrimitive("ignored"); result != unavailableCgroup("linux_amd64_required") {
		t.Fatalf("result=%+v", result)
	}
}
