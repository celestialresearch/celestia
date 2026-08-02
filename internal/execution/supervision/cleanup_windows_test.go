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
	"context"
	"errors"

	"strings"
	"testing"
	"time"
)

func TestCleanupRemainingExpiresAtZero(t *testing.T) {
	if remaining := cleanupRemaining(time.Now().Add(-time.Second)); remaining != 0 {
		t.Fatalf("remaining=%s", remaining)
	}
}

func TestCleanupFailurePreservesPrimaryStatus(t *testing.T) {
	for _, initial := range []Status{Completed, TimedOut, Cancelled, ExitFailed} {
		status, err, complete := applyStreamResult(
			initial,
			errors.New("primary"),
			true,
			streamResult{cleanupErr: errors.New("cleanup")},
			"output",
			OutputOverflow,
		)
		if status != initial || err == nil || complete {
			t.Fatalf("initial=%s status=%s complete=%t error=%v", initial, status, complete, err)
		}
	}
}

func TestTerminationFailurePreservesPrimaryCause(t *testing.T) {
	primary := context.DeadlineExceeded
	cause, complete := terminateForCleanup(primary, func() error {
		return errors.New("termination failed")
	})
	if complete ||
		!errors.Is(cause, primary) ||
		!strings.Contains(cause.Error(), "termination failed") {
		t.Fatalf("complete=%t error=%v", complete, cause)
	}
}

type cleanupProcessCase struct {
	name          string
	status        Status
	treeEmpty     func() (bool, error)
	terminate     func() error
	wait          func(time.Duration) (bool, error)
	wantComplete  bool
	wantTerminate bool
	wantError     string
}

func TestCleanupProcessTreeStates(t *testing.T) {
	runCleanupProcessCases(t, []cleanupProcessCase{
		{
			name:         "completed empty tree",
			status:       Completed,
			treeEmpty:    func() (bool, error) { return true, nil },
			terminate:    func() error { return nil },
			wait:         func(time.Duration) (bool, error) { return true, nil },
			wantComplete: true,
		},
		{
			name:          "completed populated tree",
			status:        Completed,
			treeEmpty:     func() (bool, error) { return false, nil },
			terminate:     func() error { return nil },
			wait:          func(time.Duration) (bool, error) { return true, nil },
			wantComplete:  true,
			wantTerminate: true,
		},
		{
			name:          "tree query failure",
			status:        Completed,
			treeEmpty:     func() (bool, error) { return false, errors.New("tree") },
			terminate:     func() error { return nil },
			wait:          func(time.Duration) (bool, error) { return true, nil },
			wantTerminate: true,
			wantError:     "tree",
		},
	})
}

func TestCleanupProcessFailureStates(t *testing.T) {
	runCleanupProcessCases(t, []cleanupProcessCase{
		{
			name:          "termination failure",
			status:        TimedOut,
			treeEmpty:     func() (bool, error) { return true, nil },
			terminate:     func() error { return errors.New("terminate") },
			wait:          func(time.Duration) (bool, error) { return true, nil },
			wantTerminate: true,
			wantError:     "terminate",
		},
		{
			name:          "wait failure",
			status:        Cancelled,
			treeEmpty:     func() (bool, error) { return true, nil },
			terminate:     func() error { return nil },
			wait:          func(time.Duration) (bool, error) { return false, errors.New("wait") },
			wantTerminate: true,
			wantError:     "wait",
		},
	})
}

func runCleanupProcessCases(t *testing.T, tests []cleanupProcessCase) {
	t.Helper()
	primary := context.DeadlineExceeded
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terminated := false
			terminate := func() error {
				terminated = true
				return test.terminate()
			}
			complete, err := cleanupProcessWith(
				test.status,
				primary,
				time.Now().Add(time.Second),
				test.treeEmpty,
				terminate,
				test.wait,
			)
			if complete != test.wantComplete || terminated != test.wantTerminate {
				t.Fatalf("complete=%t terminated=%t", complete, terminated)
			}
			if !errors.Is(err, primary) {
				t.Fatalf("primary error lost: %v", err)
			}
			if test.wantError != "" && !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v, want %q", err, test.wantError)
			}
		})
	}
}

func TestFinalCleanupDeadline(t *testing.T) {
	complete, err := finaliseCleanup(time.Now().Add(time.Second), func() error {
		return nil
	})
	if !complete || err != nil {
		t.Fatalf("timely cleanup: complete=%t error=%v", complete, err)
	}
	complete, err = finaliseCleanup(time.Now().Add(time.Millisecond), func() error {
		time.Sleep(2 * time.Millisecond)
		return nil
	})
	if complete || err == nil {
		t.Fatalf("late cleanup: complete=%t error=%v", complete, err)
	}
	called := false
	complete, err = finaliseCleanup(time.Now().Add(-time.Second), func() error {
		called = true
		return nil
	})
	if !called || complete || err == nil {
		t.Fatalf("overdue cleanup: called=%t complete=%t error=%v", called, complete, err)
	}
}
