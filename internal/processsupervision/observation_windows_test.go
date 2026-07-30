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

package processsupervision

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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

func TestCleanupRemainingExpiresAtZero(t *testing.T) {
	if remaining := cleanupRemaining(time.Now().Add(-time.Second)); remaining != 0 {
		t.Fatalf("remaining=%s", remaining)
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

func TestAwaitInputStates(t *testing.T) {
	writer := &inputWriter{done: make(chan struct{})}
	close(writer.done)
	deadline := time.Now().Add(time.Second)
	if result := awaitInput(writer, deadline, deadline); result != (inputResult{}) {
		t.Fatalf("completed input: %+v", result)
	}
	deadline = time.Now().Add(time.Millisecond)
	if result := awaitInput(nil, deadline, deadline.Add(100*time.Millisecond)); result.cleanupErr == nil {
		t.Fatal("blocked input join did not time out")
	}
}

func TestAwaitInputPrefersCompletedResultAtDeadline(t *testing.T) {
	for range 1_000 {
		writer := &inputWriter{done: make(chan struct{})}
		close(writer.done)
		result := awaitInput(
			writer,
			time.Now().Add(-time.Second),
			time.Now().Add(-time.Second),
		)
		if result.cleanupErr != nil {
			t.Fatalf("completed input reported cleanup failure: %v", result.cleanupErr)
		}
	}
}

func TestAwaitInputJoinDeadline(t *testing.T) {
	writer := &inputWriter{done: make(chan struct{})}
	result := awaitInput(
		writer,
		time.Now().Add(-time.Second),
		time.Now().Add(-time.Second),
	)
	if result.joinErr == nil {
		t.Fatal("unjoined input accepted")
	}
}

func TestAwaitInputCancelsBlockedWrite(t *testing.T) {
	read, write := nativePipe(t)
	defer closeNativeHandle(t, read)
	writer := newInputWriter(write)
	result := make(chan inputResult, 1)
	go writer.publish(make([]byte, 1<<20), result)
	deadline := time.Now().Add(time.Millisecond)
	observation := awaitInput(writer, deadline, deadline.Add(100*time.Millisecond))
	if observation.joinErr == nil || !strings.Contains(observation.joinErr.Error(), "join worker input") {
		t.Fatalf("input result=%v, want bounded join error", observation.joinErr)
	}
	select {
	case <-writer.done:
	default:
		t.Fatal("input writer remained active")
	}
}

func TestAwaitStreamCancelsBlockedRead(t *testing.T) {
	read, write := nativePipe(t)
	defer closeNativeHandle(t, write)
	result := make(chan streamResult, 1)
	reader := newStreamReader("output", read)
	go reader.read(8, OutputOverflow, result, make(chan Status, 1))
	deadline := time.Now().Add(time.Millisecond)
	observation := awaitStream(reader, result, deadline, deadline.Add(100*time.Millisecond))
	if observation.cleanupErr == nil || !strings.Contains(observation.cleanupErr.Error(), "join worker output") {
		t.Fatalf("stream result=%v, want bounded join error", observation.cleanupErr)
	}
	select {
	case <-reader.done:
	default:
		t.Fatal("stream reader survived bounded join")
	}
	select {
	case value := <-result:
		t.Fatalf("unjoined stream result=%v", value)
	default:
	}
}

func TestAwaitStreamJoinDeadline(t *testing.T) {
	reader := &streamReader{
		name: "output",
		done: make(chan struct{}),
	}
	result := awaitStream(
		reader,
		make(chan streamResult),
		time.Now().Add(-time.Second),
		time.Now().Add(-time.Second),
	)
	if result.cleanupErr == nil {
		t.Fatal("unjoined stream accepted")
	}
}

func TestAwaitStreamPrefersCompletedResultAtDeadline(t *testing.T) {
	for range 1_000 {
		done := make(chan struct{})
		close(done)
		result := make(chan streamResult, 1)
		result <- streamResult{data: []byte("complete")}
		got := awaitStream(
			&streamReader{name: "output", done: done},
			result,
			time.Now().Add(-time.Second),
			time.Now().Add(-time.Second),
		)
		if got.cleanupErr != nil || string(got.data) != "complete" {
			t.Fatalf("completed stream reported cleanup failure: %+v", got)
		}
	}
}

func TestResolveStreamDeadlinePrefersCompletedResult(t *testing.T) {
	done := make(chan struct{})
	close(done)
	result := make(chan streamResult, 1)
	result <- streamResult{data: []byte("complete")}
	got := resolveStreamDeadline(
		&streamReader{name: "output", done: done},
		result,
		time.Now().Add(-time.Second),
	)
	if got.cleanupErr != nil || string(got.data) != "complete" {
		t.Fatalf("completed stream reported cleanup failure: %+v", got)
	}
}

func TestAppliedInputResultIsNotAppliedTwice(t *testing.T) {
	sentinel := errors.New("input")
	input := make(chan inputResult, 1)
	input <- inputResult{err: sentinel}
	status, err, applied := awaitProcessWithInput(
		context.Background(),
		make(chan time.Time),
		make(chan time.Time),
		func() (bool, error) { return false, nil },
		make(chan Status),
		input,
	)
	if status != ExitFailed || !errors.Is(err, sentinel) || !applied {
		t.Fatalf("boundary = %s, %v, %t", status, err, applied)
	}
	if got := unappliedInputResult(inputResult{err: sentinel}, applied); got.err != nil {
		t.Fatalf("applied input was retained: %v", got.err)
	}
}

func TestCompletedProcessRetainsUnappliedInputFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("input")
	input := make(chan inputResult, 1)
	input <- inputResult{err: sentinel}
	probes := 0
	status, err, applied := awaitProcessWithInput(
		context.Background(),
		make(chan time.Time),
		make(chan time.Time),
		func() (bool, error) {
			probes++
			return probes > 1, nil
		},
		make(chan Status),
		input,
	)
	if status != Completed || err != nil || applied {
		t.Fatalf("boundary = %s, %v, %t", status, err, applied)
	}
	got := unappliedInputResult(inputResult{err: sentinel}, applied)
	if !errors.Is(got.err, sentinel) {
		t.Fatalf("unapplied input error = %v", got.err)
	}
	got = unappliedInputResult(inputResult{
		err:        errors.New("applied"),
		cleanupErr: errors.New("applied cleanup"),
		joinErr:    sentinel,
	}, true)
	if got.err != nil || got.cleanupErr == nil ||
		!errors.Is(got.joinErr, sentinel) {
		t.Fatalf("applied input result = %+v", got)
	}
}

func TestCompletionFollowsResultPublication(t *testing.T) {
	streamDone := make(chan struct{})
	streamResult := make(chan streamResult, 1)
	reader := &streamReader{
		name: "invalid",
		done: streamDone,
	}
	go reader.read(1, OutputOverflow, streamResult, make(chan Status, 1))
	<-streamDone
	select {
	case <-streamResult:
	default:
		t.Fatal("stream completed before publishing its result")
	}

	inputResult := make(chan inputResult, 1)
	writer := &inputWriter{done: make(chan struct{})}
	go writer.publish(nil, inputResult)
	<-writer.done
	select {
	case <-inputResult:
	default:
		t.Fatal("input completed before publishing its process result")
	}
}

func TestStreamResultStates(t *testing.T) {
	status, err, complete := applyStreamResult(Completed, nil, true, streamResult{err: errStreamLimit}, "output", OutputOverflow)
	if status != OutputOverflow || !errors.Is(err, errStreamLimit) || !complete {
		t.Fatalf("overflow: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyStreamResult(CleanupFailed, errors.New("cleanup"), false, streamResult{err: errors.New("read")}, "output", OutputOverflow)
	if status != CleanupFailed || err == nil || complete {
		t.Fatalf("cleanup precedence: status=%s complete=%t error=%v", status, complete, err)
	}
	status, err, complete = applyStreamResult(Completed, nil, true, streamResult{cleanupErr: errors.New("close")}, "output", OutputOverflow)
	if status != Completed || err == nil || complete {
		t.Fatalf("stream cleanup: status=%s complete=%t error=%v", status, complete, err)
	}
}

func TestStreamReadFailure(t *testing.T) {
	status, err, complete := applyStreamResult(
		Completed,
		nil,
		true,
		streamResult{err: errors.New("read")},
		"output",
		OutputOverflow,
	)
	if status != ExitFailed || err == nil || !complete {
		t.Fatalf("stream read: status=%s complete=%t error=%v", status, complete, err)
	}
}

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

func TestReadPipeStates(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		read, write := nativePipe(t)
		closeNativeHandle(t, write)
		result := make(chan streamResult, 1)
		reader := newStreamReader("output", read)
		reader.read(8, OutputOverflow, result, make(chan Status, 1))
		observation := <-result
		if len(observation.data) != 0 || observation.err != nil {
			t.Fatalf("empty pipe: data=%q error=%v", observation.data, observation.err)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		read, write := nativePipe(t)
		file := os.NewFile(uintptr(write), "test-pipe")
		if _, err := file.Write(bytes.Repeat([]byte("x"), 16)); err != nil {
			t.Fatalf("write pipe: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close pipe: %v", err)
		}
		result := make(chan streamResult, 1)
		overflow := make(chan Status, 1)
		reader := newStreamReader("output", read)
		reader.read(8, OutputOverflow, result, overflow)
		if !errors.Is((<-result).err, errStreamLimit) || <-overflow != OutputOverflow {
			t.Fatal("pipe overflow was not reported")
		}
	})
	t.Run("full overflow signal", testFullOverflowSignal)
}

func testFullOverflowSignal(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "overflow")
	if err != nil {
		t.Fatalf("create stream: %v", err)
	}
	defer closeFile(t, file)
	if _, err := file.Write(bytes.Repeat([]byte("x"), 16)); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("rewind stream: %v", err)
	}
	overflow := make(chan Status, 1)
	overflow <- ErrorOverflow
	result := make(chan streamResult, 1)
	reader := &streamReader{name: "output", file: file}
	go func() {
		result <- reader.readResult(8, OutputOverflow, overflow)
	}()
	select {
	case observation := <-result:
		if !errors.Is(observation.err, errStreamLimit) ||
			len(observation.data) != 8 {
			t.Fatalf(
				"stream length=%d error=%v",
				len(observation.data),
				observation.err,
			)
		}
	case <-time.After(time.Second):
		<-overflow
		t.Fatal("full overflow signal blocked stream completion")
	}
	if status := <-overflow; status != ErrorOverflow {
		t.Fatalf("existing overflow signal changed to %s", status)
	}
}
