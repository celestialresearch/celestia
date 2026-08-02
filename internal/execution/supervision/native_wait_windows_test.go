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
	"golang.org/x/sys/windows"

	"strings"
	"testing"
	"time"
)

func TestNativeWaitRejectsInvalidState(t *testing.T) {
	t.Run("read handle", func(t *testing.T) {
		result := make(chan streamResult, 1)
		overflow := make(chan Status, 1)
		reader := newStreamReader("output", windows.InvalidHandle)
		reader.read(1, OutputOverflow, result, overflow)
		if (<-result).err == nil {
			t.Fatal("invalid read handle was accepted")
		}
	})
	t.Run("cleanup timeout", func(t *testing.T) {
		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			t.Fatalf("create event: %v", err)
		}
		defer closeNativeHandle(t, event)
		job, complete, err := createJob(testNativeLimits())
		if err != nil {
			t.Fatalf("create job: %v", err)
		}
		if !complete {
			t.Fatal("successful job creation reported incomplete cleanup")
		}
		defer closeNativeHandle(t, job)
		if complete, err := waitCleanup(event, job, time.Millisecond); complete || err == nil {
			t.Fatal("unsignalled process did not time out")
		}
	})
	t.Run("job handle", func(t *testing.T) {
		if _, err := jobEmpty(windows.InvalidHandle); err == nil {
			t.Fatal("invalid job handle was accepted")
		}
	})
	t.Run("wait handle", func(t *testing.T) {
		if complete, err := waitCleanup(
			windows.InvalidHandle,
			windows.InvalidHandle,
			time.Millisecond,
		); complete || err == nil {
			t.Fatal("invalid wait handles were accepted")
		}
	})
}

func TestWaitMillisecondsRoundsUp(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    uint32
	}{
		{name: "zero", timeout: 0, want: 0},
		{name: "negative", timeout: -time.Nanosecond, want: 0},
		{name: "whole", timeout: time.Millisecond, want: 1},
		{name: "sub-millisecond", timeout: time.Nanosecond, want: 1},
		{name: "fractional", timeout: time.Millisecond + time.Nanosecond, want: 2},
		{name: "clamped", timeout: time.Duration(1<<63 - 1), want: ^uint32(0) - 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := waitMilliseconds(test.timeout); got != test.want {
				t.Fatalf("waitMilliseconds(%s) = %d, want %d", test.timeout, got, test.want)
			}
		})
	}
}

type waitCleanupCase struct {
	name         string
	event        uint32
	waitErr      error
	emptyResults []bool
	emptyErr     error
	times        []time.Time
	wantComplete bool
	wantError    string
	wantSleeps   int
}

func TestWaitCleanupProcessStates(t *testing.T) {
	runWaitCleanupCases(t, []waitCleanupCase{
		{
			name:      "wait failure",
			waitErr:   errors.New("wait"),
			times:     []time.Time{time.Unix(0, 0)},
			wantError: "wait for worker cleanup",
		},
		{
			name:      "process timeout",
			event:     uint32(windows.WAIT_TIMEOUT),
			times:     []time.Time{time.Unix(0, 0)},
			wantError: "worker cleanup deadline",
		},
		{
			name:      "unexpected event",
			event:     42,
			times:     []time.Time{time.Unix(0, 0)},
			wantError: "unexpected worker wait",
		},
	})
}

func TestWaitCleanupTreeStates(t *testing.T) {
	runWaitCleanupCases(t, []waitCleanupCase{
		{
			name:         "empty tree",
			event:        windows.WAIT_OBJECT_0,
			emptyResults: []bool{true},
			times:        []time.Time{time.Unix(0, 0)},
			wantComplete: true,
		},
		{
			name:         "job query failure",
			event:        windows.WAIT_OBJECT_0,
			emptyErr:     errors.New("job"),
			times:        []time.Time{time.Unix(0, 0)},
			wantError:    "job",
			emptyResults: []bool{false},
		},
		{
			name:         "tree becomes empty",
			event:        windows.WAIT_OBJECT_0,
			emptyResults: []bool{false, true},
			times:        []time.Time{time.Unix(0, 0), time.Unix(0, 0)},
			wantComplete: true,
			wantSleeps:   1,
		},
		{
			name:         "tree deadline",
			event:        windows.WAIT_OBJECT_0,
			emptyResults: []bool{false},
			times:        []time.Time{time.Unix(0, 0), time.Unix(1, 0)},
			wantError:    "process tree cleanup deadline",
		},
	})
}

func TestWaitCleanupRejectsRoundedOverrun(t *testing.T) {
	started := time.Unix(0, 0)
	times := []time.Time{started, started.Add(time.Millisecond)}
	index := 0
	complete, err := waitCleanupWith(
		windows.Handle(7),
		time.Nanosecond,
		func(_ windows.Handle, timeout uint32) (uint32, error) {
			if timeout != 1 {
				t.Fatalf("timeout=%d", timeout)
			}
			return windows.WAIT_OBJECT_0, nil
		},
		func() (bool, error) {
			t.Fatal("queried job after cleanup deadline")
			return true, nil
		},
		func() time.Time {
			value := times[min(index, len(times)-1)]
			index++
			return value
		},
		func(time.Duration) {},
	)
	if complete || err == nil ||
		!strings.Contains(err.Error(), "process tree cleanup deadline") {
		t.Fatalf("complete=%t error=%v", complete, err)
	}
}

func runWaitCleanupCases(t *testing.T, tests []waitCleanupCase) {
	t.Helper()
	process := windows.Handle(7)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timeIndex := 0
			now := func() time.Time {
				index := min(timeIndex, len(test.times)-1)
				timeIndex++
				return test.times[index]
			}
			emptyIndex := 0
			empty := func() (bool, error) {
				index := min(emptyIndex, len(test.emptyResults)-1)
				emptyIndex++
				return test.emptyResults[index], test.emptyErr
			}
			sleeps := 0
			complete, err := waitCleanupWith(
				process,
				time.Second,
				func(handle windows.Handle, timeout uint32) (uint32, error) {
					if handle != process || timeout != 1000 {
						t.Fatalf("handle=%d timeout=%d", handle, timeout)
					}
					return test.event, test.waitErr
				},
				empty,
				now,
				func(time.Duration) { sleeps++ },
			)
			if complete != test.wantComplete || sleeps != test.wantSleeps {
				t.Fatalf("complete=%t sleeps=%d", complete, sleeps)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("error=%v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v, want %q", err, test.wantError)
			}
		})
	}
}
