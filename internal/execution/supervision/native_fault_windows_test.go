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
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPipeCreationFailures(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			calls := 0
			_, complete, err := newPipesWith(
				func(read, write *windows.Handle, _ *windows.SecurityAttributes, _ uint32) error {
					calls++
					if calls == failAt {
						return errors.New("create")
					}
					*read = windows.InvalidHandle
					*write = windows.InvalidHandle
					return nil
				},
				func(windows.Handle, uint32, uint32) error { return nil },
			)
			if err == nil || calls != failAt {
				t.Fatalf("calls=%d complete=%t error=%v", calls, complete, err)
			}
			if !complete {
				t.Fatalf("failAt=%d cleanup incomplete", failAt)
			}
		})
	}
}

func TestPipeRestrictionFailure(t *testing.T) {
	restrictCalls := 0
	_, complete, err := newPipesWith(
		func(read, write *windows.Handle, _ *windows.SecurityAttributes, _ uint32) error {
			*read = windows.InvalidHandle
			*write = windows.InvalidHandle
			return nil
		},
		func(windows.Handle, uint32, uint32) error {
			restrictCalls++
			return errors.New("restrict")
		},
	)
	if !complete || err == nil || restrictCalls != 1 ||
		!strings.Contains(err.Error(), "restrict parent pipe") {
		t.Fatalf("calls=%d complete=%t error=%v", restrictCalls, complete, err)
	}
}

func TestJobCreationFailure(t *testing.T) {
	_, complete, err := createJobWith(
		testNativeLimits(),
		func() (windows.Handle, error) { return 0, errors.New("create") },
		func(windows.Handle, windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
			t.Fatal("configure called")
			return nil
		},
		func(windows.Handle) error {
			t.Fatal("close called")
			return nil
		},
	)
	if !complete || err == nil || !strings.Contains(err.Error(), "create job") {
		t.Fatalf("complete=%t error=%v", complete, err)
	}
}

func TestJobConfigurationAndCleanup(t *testing.T) {
	limits := testNativeLimits()
	const job = windows.Handle(17)
	configureErr := errors.New("configure")
	closeErr := errors.New("close")
	_, complete, err := createJobWith(
		limits,
		func() (windows.Handle, error) { return job, nil },
		func(handle windows.Handle, information windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
			assertJobLimits(t, handle, job, &information, limits)
			return configureErr
		},
		func(handle windows.Handle) error {
			if handle != job {
				t.Fatalf("closed handle=%d", handle)
			}
			return closeErr
		},
	)
	if complete || !errors.Is(err, configureErr) || !errors.Is(err, closeErr) {
		t.Fatalf("complete=%t error=%v", complete, err)
	}
}

func TestJobConfigurationSuccess(t *testing.T) {
	limits := testNativeLimits()
	const job = windows.Handle(19)
	result, complete, err := createJobWith(
		limits,
		func() (windows.Handle, error) { return job, nil },
		func(handle windows.Handle, information windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
			assertJobLimits(t, handle, job, &information, limits)
			return nil
		},
		func(windows.Handle) error {
			t.Fatal("close called")
			return nil
		},
	)
	if result != job || !complete || err != nil {
		t.Fatalf("job=%d complete=%t error=%v", result, complete, err)
	}
}

func assertJobLimits(
	t *testing.T,
	handle,
	want windows.Handle,
	information *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
	limits Limits,
) {
	t.Helper()
	if handle != want ||
		information.BasicLimitInformation.PerProcessUserTimeLimit != limits.Timeout.Nanoseconds()/100 ||
		information.BasicLimitInformation.ActiveProcessLimit != limits.Processes ||
		information.JobMemoryLimit != uintptr(limits.MemoryBytes) {
		t.Fatalf("handle=%d limits=%+v", handle, information)
	}
	required := uint32(
		windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
			windows.JOB_OBJECT_LIMIT_PROCESS_TIME |
			windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
			windows.JOB_OBJECT_LIMIT_JOB_MEMORY,
	)
	if information.BasicLimitInformation.LimitFlags != required {
		t.Fatalf("limit flags=%#x want=%#x", information.BasicLimitInformation.LimitFlags, required)
	}
}
