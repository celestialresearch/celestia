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
	"golang.org/x/sys/windows"

	"testing"
	"time"
)

func TestAwaitProcessStates(t *testing.T) {
	t.Run("wait error", func(t *testing.T) {
		status, err := awaitProcess(context.Background(), make(chan time.Time), make(chan time.Time), func() (bool, error) {
			return false, errors.New("wait")
		}, make(chan Status), make(chan inputResult))
		if status != ExitFailed || err == nil {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		timeout := make(chan time.Time, 1)
		timeout <- time.Now()
		status, err := awaitProcess(context.Background(), timeout, make(chan time.Time), func() (bool, error) {
			return false, nil
		}, make(chan Status), make(chan inputResult))
		if status != TimedOut || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("ready completion wins at timeout cutoff", func(t *testing.T) {
		timeout := make(chan time.Time, 1)
		timeout <- time.Now()
		status, err := awaitProcess(context.Background(), timeout, make(chan time.Time), func() (bool, error) {
			return true, nil
		}, make(chan Status), make(chan inputResult))
		if status != Completed || err != nil {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("ready completion wins at cancellation cutoff", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		status, err := awaitProcess(ctx, make(chan time.Time), make(chan time.Time), func() (bool, error) {
			return true, nil
		}, make(chan Status), make(chan inputResult))
		if status != Completed || err != nil {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		overflow := make(chan Status, 1)
		overflow <- OutputOverflow
		status, err := awaitProcess(context.Background(), make(chan time.Time), make(chan time.Time), func() (bool, error) {
			return false, nil
		}, overflow, make(chan inputResult))
		if status != OutputOverflow || !errors.Is(err, errStreamLimit) {
			t.Fatalf("status=%s error=%v", status, err)
		}
	})
}

func TestAwaitProcessKeepsTimeout(t *testing.T) {
	timeout := make(chan time.Time, 1)
	timeout <- time.Now()
	input := make(chan inputResult, 1)
	input <- inputResult{}
	result := make(chan struct {
		status Status
		err    error
	}, 1)
	go func() {
		status, err := awaitProcess(context.Background(), timeout, make(chan time.Time), func() (bool, error) {
			return false, nil
		}, make(chan Status), input)
		result <- struct {
			status Status
			err    error
		}{status: status, err: err}
	}()
	select {
	case outcome := <-result:
		if outcome.status != TimedOut || !errors.Is(outcome.err, context.DeadlineExceeded) {
			t.Fatalf("status=%s error=%v", outcome.status, outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout outcome was discarded")
	}
}

func TestAwaitProcessKeepsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, test := range []struct {
		name     string
		overflow chan Status
		input    chan inputResult
	}{
		{
			name:     "input cleanup failure",
			overflow: make(chan Status),
			input:    bufferedInputFailure(),
		},
		{
			name:     "output overflow",
			overflow: bufferedOverflow(),
			input:    make(chan inputResult),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for range 100 {
				status, err := awaitProcess(
					ctx,
					make(chan time.Time),
					make(chan time.Time),
					func() (bool, error) { return false, nil },
					test.overflow,
					test.input,
				)
				if status != Cancelled || !errors.Is(err, context.Canceled) {
					t.Fatalf("status=%s error=%v", status, err)
				}
			}
		})
	}
}

func bufferedInputFailure() chan inputResult {
	input := make(chan inputResult, 1)
	input <- inputResult{cleanupErr: errors.New("cleanup")}
	return input
}

func bufferedOverflow() chan Status {
	overflow := make(chan Status, 1)
	overflow <- OutputOverflow
	return overflow
}

func TestAwaitProcessRechecksCompletionAfterLowerPriorityEvent(t *testing.T) {
	for _, test := range []struct {
		name     string
		overflow chan Status
		input    chan inputResult
	}{
		{
			name:     "input",
			overflow: make(chan Status),
			input:    bufferedInputFailure(),
		},
		{
			name:     "overflow",
			overflow: bufferedOverflow(),
			input:    make(chan inputResult),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			checks := 0
			status, err := awaitProcess(
				context.Background(),
				make(chan time.Time),
				make(chan time.Time),
				func() (bool, error) {
					checks++
					return checks == 2, nil
				},
				test.overflow,
				test.input,
			)
			if status != Completed || err != nil {
				t.Fatalf("status=%s error=%v", status, err)
			}
		})
	}
}

func TestAwaitProcessInputFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  inputResult
		status Status
	}{
		{
			name:   "write failure",
			input:  inputResult{err: errors.New("write")},
			status: ExitFailed,
		},
		{
			name:   "cleanup failure",
			input:  inputResult{cleanupErr: errors.New("cleanup")},
			status: CleanupFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := make(chan inputResult, 1)
			input <- test.input
			status, err := awaitProcess(
				context.Background(),
				make(chan time.Time),
				make(chan time.Time),
				func() (bool, error) { return false, nil },
				make(chan Status),
				input,
			)
			if status != test.status || err == nil {
				t.Fatalf("status=%s error=%v", status, err)
			}
		})
	}
}

func TestAwaitProcessPollsCompletion(t *testing.T) {
	poll := make(chan time.Time, 1)
	poll <- time.Now()
	status, err := awaitProcess(
		context.Background(),
		make(chan time.Time),
		poll,
		func() (bool, error) { return true, nil },
		make(chan Status),
		make(chan inputResult),
	)
	if status != Completed || err != nil {
		t.Fatalf("status=%s error=%v", status, err)
	}
}

func TestAwaitProcessReceivesBoundaryEvents(t *testing.T) {
	type result struct {
		status Status
		err    error
	}
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		checked := make(chan struct{})
		results := make(chan result, 1)
		go func() {
			status, err := awaitProcess(
				ctx,
				make(chan time.Time),
				make(chan time.Time),
				func() (bool, error) {
					select {
					case <-checked:
					default:
						close(checked)
					}
					return false, nil
				},
				make(chan Status),
				make(chan inputResult),
			)
			results <- result{status: status, err: err}
		}()
		<-checked
		cancel()
		got := <-results
		if got.status != Cancelled || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("status = %s error = %v", got.status, got.err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		timeout := make(chan time.Time)
		checked := make(chan struct{})
		results := make(chan result, 1)
		go func() {
			status, err := awaitProcess(
				context.Background(),
				timeout,
				make(chan time.Time),
				func() (bool, error) {
					select {
					case <-checked:
					default:
						close(checked)
					}
					return false, nil
				},
				make(chan Status),
				make(chan inputResult),
			)
			results <- result{status: status, err: err}
		}()
		<-checked
		timeout <- time.Now()
		got := <-results
		if got.status != TimedOut || !errors.Is(got.err, context.DeadlineExceeded) {
			t.Fatalf("status = %s error = %v", got.status, got.err)
		}
	})
}

func TestExecutionAllowanceStartsAtResume(t *testing.T) {
	started := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	now := started.Add(750 * time.Millisecond)
	if remaining := executionRemaining(started, 2*time.Second, now); remaining != 1250*time.Millisecond {
		t.Fatalf("remaining allowance=%s", remaining)
	}
	if remaining := executionRemaining(started, 2*time.Second, started.Add(3*time.Second)); remaining >= 0 {
		t.Fatalf("expired allowance=%s", remaining)
	}
}

func TestEarliestDeadline(t *testing.T) {
	t.Parallel()
	first := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	second := first.Add(time.Second)
	if got := earliestDeadline(first, second); !got.Equal(first) {
		t.Fatalf("earliestDeadline(first, second) = %s", got)
	}
	if got := earliestDeadline(second, first); !got.Equal(first) {
		t.Fatalf("earliestDeadline(second, first) = %s", got)
	}
}

func TestExecutionAllowanceIsPositive(t *testing.T) {
	if allowance := executionAllowance(0); allowance != time.Nanosecond {
		t.Fatalf("zero allowance = %s", allowance)
	}
	if allowance := executionAllowance(time.Second); allowance != time.Second {
		t.Fatalf("positive allowance = %s", allowance)
	}
}

func TestProcessCompleteStates(t *testing.T) {
	tests := []struct {
		name         string
		event        uint32
		waitErr      error
		wantComplete bool
		wantError    bool
	}{
		{name: "complete", event: windows.WAIT_OBJECT_0, wantComplete: true},
		{name: "active", event: uint32(windows.WAIT_TIMEOUT)},
		{name: "wait failure", waitErr: errors.New("wait"), wantError: true},
		{name: "unexpected event", event: 42, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			complete, err := processCompleteWith(1, func(handle windows.Handle, timeout uint32) (uint32, error) {
				if handle != 1 || timeout != 0 {
					t.Fatalf("handle=%d timeout=%d", handle, timeout)
				}
				return test.event, test.waitErr
			})
			if complete != test.wantComplete || (err != nil) != test.wantError {
				t.Fatalf("complete=%t error=%v", complete, err)
			}
		})
	}
}

func TestResolveProcessBoundaryStates(t *testing.T) {
	status, err := resolveProcessBoundary(
		func() (bool, error) { return true, nil },
		TimedOut,
		context.DeadlineExceeded,
	)
	if status != Completed || err != nil {
		t.Fatalf("completed status=%s error=%v", status, err)
	}
	waitErr := errors.New("wait")
	status, err = resolveProcessBoundary(
		func() (bool, error) { return false, waitErr },
		TimedOut,
		context.DeadlineExceeded,
	)
	if status != ExitFailed || !errors.Is(err, waitErr) {
		t.Fatalf("failed status=%s error=%v", status, err)
	}
	status, err = resolveProcessBoundary(
		func() (bool, error) { return false, nil },
		Cancelled,
		context.Canceled,
	)
	if status != Cancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("pending status=%s error=%v", status, err)
	}
}
