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

//go:build linux && amd64

package linuxamd64feasibility

import (
	"os"
	"testing"
)

func TestClone3CgroupPrimitiveNative(t *testing.T) {
	root := os.Getenv("CELESTIA_CGROUP_ROOT")
	if root == "" {
		return
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	result := clone3CgroupPrimitive(root, clone3TestCommand(t), file)
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result=%+v cause=%v", result, result.cause)
	}
}
