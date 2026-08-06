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
	"errors"
	"testing"
)

func TestDurabilityCleanupPreservesPrimitiveOutcome(t *testing.T) {
	primary := unavailableDurability("first_refusal")
	complete := finishDurabilityCleanup(primary, nil)
	if complete.Outcome != primary.Outcome || complete.Reason != primary.Reason ||
		!complete.CleanupAttempted || !complete.CleanupComplete {
		t.Fatalf("complete=%+v", complete)
	}
	failed := finishDurabilityCleanup(primary, errors.New("cleanup failed"))
	if failed.Outcome != primary.Outcome || failed.Reason != primary.Reason ||
		!failed.CleanupAttempted || failed.CleanupComplete {
		t.Fatalf("failed=%+v", failed)
	}
}
