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

package attempt

import (
	"errors"
	"testing"
)

func TestProgressTerminal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		progress  Progress
		cancelled bool
		want      State
	}{
		"preparation failure": {want: StateFailed},
		"cancelled before commit": {
			progress: Progress{Prepared: true}, cancelled: true, want: StateCancelled,
		},
		"native refusal": {
			progress: Progress{Prepared: true, CommitAttempted: true, NativeResult: true},
			want:     StateFailed,
		},
		"commit result missing": {
			progress: Progress{Prepared: true, CommitAttempted: true},
			want:     StateIndeterminate,
		},
		"observation mismatch": {
			progress: Progress{
				Prepared: true, CommitAttempted: true, NativeResult: true,
				NativeSucceeded: true, Observed: true,
			},
			want: StateIndeterminate,
		},
		"verified": {
			progress: Progress{
				Prepared: true, CommitAttempted: true, NativeResult: true,
				NativeSucceeded: true, Observed: true, Matched: true,
			},
			want: StateVerified,
		},
		"recovered verified": {
			progress: Progress{
				Prepared: true, CommitAttempted: true, Observed: true, Matched: true,
			},
			want: StateVerified,
		},
		"contradictory native failure": {
			progress: Progress{
				Prepared: true, CommitAttempted: true, NativeResult: true,
				Observed: true, Matched: true,
			},
			want: StateIndeterminate,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := test.progress.Terminal(test.cancelled)
			if err != nil || got != test.want {
				t.Fatalf("Terminal() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestProgressRejectsContradictions(t *testing.T) {
	t.Parallel()

	invalid := []Progress{
		{CommitAttempted: true},
		{NativeResult: true},
		{Prepared: true, NativeSucceeded: true},
		{Prepared: true, Observed: true},
	}
	for _, progress := range invalid {
		if _, err := progress.Terminal(false); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("Terminal(%+v) error = %v", progress, err)
		}
	}
}
