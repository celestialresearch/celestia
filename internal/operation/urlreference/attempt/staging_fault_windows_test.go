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

//go:build windows

package attemptstore

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStageRollsBackNativeWriteFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "disk full", err: windows.ERROR_DISK_FULL},
		{name: "permission denied", err: windows.ERROR_ACCESS_DENIED},
		{name: "interrupted", err: windows.ERROR_OPERATION_ABORTED},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			accepted, admittedAt := testAccepted(t)
			request, err := validateAccepted(accepted, admittedAt)
			if err != nil {
				t.Fatalf("validate accepted request: %v", err)
			}
			_, err = store.stageOwned(
				accepted,
				request,
				admittedAt,
				nil,
				func(string, string, any) error { return test.err },
				store.createOwnershipMarkerState,
			)
			if !errors.Is(err, test.err) {
				t.Fatalf("stageOwned() error = %v, want %v", err, test.err)
			}
			if marker, markerErr := store.hasOwnershipMarker(
				request.AttemptID,
			); markerErr != nil || marker {
				t.Fatalf("ownership marker present = %t, error = %v", marker, markerErr)
			}
			if _, statErr := os.Lstat(
				store.pendingPath(request.AttemptID),
			); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("pending attempt retained: %v", statErr)
			}
		})
	}
}
