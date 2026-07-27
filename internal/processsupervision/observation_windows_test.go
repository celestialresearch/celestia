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

func TestAwaitInputStates(t *testing.T) {
	input := make(chan inputResult, 1)
	input <- inputResult{}
	deadline := time.Now().Add(time.Second)
	if result := awaitInput(nil, input, deadline, deadline); result != (inputResult{}) {
		t.Fatalf("completed input: %+v", result)
	}
	deadline = time.Now().Add(time.Millisecond)
	if result := awaitInput(nil, make(chan inputResult), deadline, deadline.Add(100*time.Millisecond)); result.cleanupErr == nil {
		t.Fatal("blocked input join did not time out")
	}
}

func TestAwaitInputCancelsBlockedWrite(t *testing.T) {
	read, write := nativePipe(t)
	defer closeNativeHandle(t, read)
	writer := newInputWriter(write)
	result := make(chan inputResult, 1)
	inputDone := make(chan inputResult, 1)
	go writer.publish(make([]byte, 1<<20), result, inputDone)
	deadline := time.Now().Add(time.Millisecond)
	observation := awaitInput(writer, result, deadline, deadline.Add(100*time.Millisecond))
	if observation.cleanupErr == nil || !strings.Contains(observation.cleanupErr.Error(), "join worker input") {
		t.Fatalf("input result=%v, want bounded join error", observation.cleanupErr)
	}
	select {
	case <-writer.done:
	default:
		t.Fatal("input writer remained active")
	}
	select {
	case <-inputDone:
	default:
		t.Fatal("input writer completed before publishing its join result")
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

	inputDone := make(chan inputResult, 1)
	inputResult := make(chan inputResult, 1)
	writer := &inputWriter{done: make(chan struct{})}
	go writer.publish(nil, inputResult, inputDone)
	<-writer.done
	select {
	case <-inputResult:
	default:
		t.Fatal("input completed before publishing its process result")
	}
	select {
	case <-inputDone:
	default:
		t.Fatal("input completed before publishing its join result")
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
}
