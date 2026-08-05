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
	"time"

	"golang.org/x/sys/windows"
)

func TestProcessResources(t *testing.T) {
	const job = windows.Handle(17)
	const process = windows.Handle(19)
	resources := processResourcesWith(job, process, func(
		handle windows.Handle,
		accounting *jobBasicAndIOAccounting,
	) error {
		if handle != job {
			t.Fatalf("job=%d", handle)
		}
		accounting.totalUserTime = 11
		accounting.totalKernelTime = 7
		accounting.io.ReadOperationCount = 1
		accounting.io.WriteOperationCount = 2
		accounting.io.OtherOperationCount = 3
		accounting.io.ReadTransferCount = 4
		accounting.io.WriteTransferCount = 5
		accounting.io.OtherTransferCount = 6
		return nil
	}, func(handle windows.Handle, limits *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
		if handle != job {
			t.Fatalf("job=%d", handle)
		}
		limits.PeakProcessMemoryUsed = 7
		limits.PeakJobMemoryUsed = 8
		return nil
	}, func(handle windows.Handle) (uint64, error) {
		if handle != process {
			t.Fatalf("process=%d", handle)
		}
		return 9, nil
	})
	if !resources.Measured || resources.Err != nil {
		t.Fatalf("resources=%+v", resources)
	}
	assertResourceValues(t, resources)
}

func assertResourceValues(t *testing.T, resources Resources) {
	t.Helper()
	if resources.CPUTime != 1800*time.Nanosecond ||
		resources.PeakWorkingSet != 9 || resources.PeakProcessCommit != 7 ||
		resources.PeakJobCommit != 8 ||
		resources.ReadOperations != 1 || resources.WriteOperations != 2 ||
		resources.OtherOperations != 3 || resources.ReadBytes != 4 ||
		resources.WriteBytes != 5 || resources.OtherBytes != 6 {
		t.Fatalf("resources=%+v", resources)
	}
}

func TestProcessResourcesRejectsQueryFailure(t *testing.T) {
	failure := errors.New("injected query failure")
	for name, queries := range map[string]struct {
		accounting queryJobAccounting
		limits     queryJobLimits
	}{
		"accounting": {accounting: func(windows.Handle, *jobBasicAndIOAccounting) error { return failure }, limits: func(windows.Handle, *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error { return nil }},
		"limits":     {accounting: func(windows.Handle, *jobBasicAndIOAccounting) error { return nil }, limits: func(windows.Handle, *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error { return failure }},
	} {
		t.Run(name, func(t *testing.T) {
			resources := processResourcesWith(17, 19, queries.accounting, queries.limits, func(windows.Handle) (uint64, error) { return 0, nil })
			if resources.Measured || !errors.Is(resources.Err, failure) ||
				resources.CPUTime != 0 || resources.PeakJobCommit != 0 {
				t.Fatalf("resources=%+v", resources)
			}
		})
	}
}

func TestProcessResourcesRejectsWorkingSetFailure(t *testing.T) {
	failure := errors.New("injected working set failure")
	resources := processResourcesWith(17, 19, func(
		_ windows.Handle,
		accounting *jobBasicAndIOAccounting,
	) error {
		accounting.totalUserTime = 3
		accounting.totalKernelTime = 2
		accounting.io.ReadOperationCount = 4
		return nil
	}, func(_ windows.Handle, limits *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
		limits.PeakProcessMemoryUsed = 5
		limits.PeakJobMemoryUsed = 6
		return nil
	}, func(windows.Handle) (uint64, error) {
		return 0, failure
	})
	if resources.Measured || !errors.Is(resources.Err, failure) ||
		resources.CPUTime != 500*time.Nanosecond ||
		resources.PeakWorkingSet != 0 || resources.PeakProcessCommit != 5 ||
		resources.PeakJobCommit != 6 || resources.ReadOperations != 4 {
		t.Fatalf("resources=%+v", resources)
	}
}

func TestProcessPeakWorkingSet(t *testing.T) {
	peak, err := processPeakWorkingSetWith(17, func(
		handle windows.Handle,
		counters *processMemoryCounters,
	) error {
		if handle != 17 || counters.size != 72 {
			t.Fatalf("handle=%d counters=%+v", handle, counters)
		}
		counters.peakWorkingSet = 31
		return nil
	})
	if err != nil || peak != 31 {
		t.Fatalf("peak=%d error=%v", peak, err)
	}
}

func TestWindowsTicksSaturates(t *testing.T) {
	if actual := windowsTicks(11, 7); actual != 1800*time.Nanosecond {
		t.Fatalf("ticks=%s", actual)
	}
	if actual := windowsTicks(1<<63-1, 1); actual != time.Duration(1<<63-1) {
		t.Fatalf("saturated ticks=%s", actual)
	}
}
