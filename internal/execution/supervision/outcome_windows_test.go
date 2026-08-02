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

//go:build windows && amd64

package supervision

import (
	"errors"

	"testing"
)

func TestStreamResultPreservesPrimaryStatus(t *testing.T) {
	for _, initial := range []Status{TimedOut, Cancelled, OutputOverflow, ErrorOverflow, ExitFailed} {
		status, err, complete := applyStreamResult(initial, errors.New("primary"), true, streamResult{err: errors.New("read")}, "output", OutputOverflow)
		if status != initial || err == nil || !complete {
			t.Fatalf("secondary read error: initial=%s status=%s complete=%t error=%v", initial, status, complete, err)
		}
	}
}

func TestReadExitPreservesPrimaryStatus(t *testing.T) {
	for _, test := range []struct {
		initial Status
		want    Status
	}{
		{initial: Completed, want: ExitFailed},
		{initial: TimedOut, want: TimedOut},
		{initial: Cancelled, want: Cancelled},
		{initial: OutputOverflow, want: OutputOverflow},
		{initial: ErrorOverflow, want: ErrorOverflow},
		{initial: CleanupFailed, want: CleanupFailed},
	} {
		status, _, err := readExit(0, test.initial, errors.New("primary"))
		if status != test.want || err == nil {
			t.Fatalf("initial=%s status=%s want=%s error=%v", test.initial, status, test.want, err)
		}
	}
}

func TestInputResultStates(t *testing.T) {
	status, err, complete := applyInputResult(Completed, nil, true, inputResult{err: errors.New("write")})
	if status != ExitFailed || err == nil || !complete {
		t.Fatalf("input error: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyInputResult(Completed, nil, true, inputResult{cleanupErr: errors.New("close")})
	if status != Completed || err == nil || complete {
		t.Fatalf("input cleanup: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyInputResult(Completed, nil, true, inputResult{joinErr: errors.New("join")})
	if status != Completed || err == nil || complete {
		t.Fatalf("input join: status=%s complete=%t error=%v", status, complete, err)
	}
}

func TestFinalCleanupProjection(t *testing.T) {
	primary := errors.New("primary")
	outcome := Outcome{CleanupComplete: true, Err: primary}
	if actual := applyFinalCleanup(outcome, true, nil); !actual.CleanupComplete ||
		!errors.Is(actual.Err, primary) {
		t.Fatalf("complete cleanup changed outcome: %+v", actual)
	}
	cleanup := errors.New("cleanup")
	actual := applyFinalCleanup(outcome, false, cleanup)
	if actual.CleanupComplete ||
		!errors.Is(actual.Err, primary) ||
		!errors.Is(actual.Err, cleanup) {
		t.Fatalf("failed cleanup outcome: %+v", actual)
	}
}
