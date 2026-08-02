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
	"bytes"
	"context"
	"errors"

	"os"
	"strings"
	"testing"
	"time"
)

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
