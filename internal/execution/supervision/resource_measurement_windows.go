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
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type jobBasicAndIOAccounting struct {
	totalUserTime   int64
	totalKernelTime int64
	_               [32]byte
	io              windows.IO_COUNTERS
}

type queryJobAccounting func(windows.Handle, *jobBasicAndIOAccounting) error
type queryJobLimits func(windows.Handle, *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error

type queryProcessMemory func(windows.Handle) (uint64, error)

var (
	psapi                = windows.NewLazySystemDLL("psapi.dll")
	getProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

type processMemoryCounters struct {
	size           uint32
	_              uint32
	peakWorkingSet uintptr
	_              [7]uintptr
}

func processResources(job, process windows.Handle) Resources {
	return processResourcesWith(
		job,
		process,
		queryAccounting,
		queryLimits,
		processPeakWorkingSet,
	)
}

func processResourcesWith(
	job, process windows.Handle,
	queryAccounting queryJobAccounting,
	queryLimits queryJobLimits,
	queryWorkingSet queryProcessMemory,
) Resources {
	resources := jobResourcesWith(job, queryAccounting, queryLimits)
	if resources.Err != nil {
		return resources
	}
	peakWorkingSet, err := queryWorkingSet(process)
	if err != nil {
		resources.Measured = false
		resources.Err = fmt.Errorf("query worker working set: %w", err)
		return resources
	}
	resources.PeakWorkingSet = peakWorkingSet
	return resources
}

func jobResourcesWith(
	job windows.Handle,
	queryAccounting queryJobAccounting,
	queryLimits queryJobLimits,
) Resources {
	var accounting jobBasicAndIOAccounting
	if err := queryAccounting(job, &accounting); err != nil {
		return Resources{Err: fmt.Errorf("query worker accounting: %w", err)}
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := queryLimits(job, &limits); err != nil {
		return Resources{Err: fmt.Errorf("query worker memory: %w", err)}
	}
	return Resources{
		CPUTime:           windowsTicks(accounting.totalUserTime, accounting.totalKernelTime),
		PeakProcessCommit: uint64(limits.PeakProcessMemoryUsed),
		PeakJobCommit:     uint64(limits.PeakJobMemoryUsed),
		ReadOperations:    accounting.io.ReadOperationCount,
		WriteOperations:   accounting.io.WriteOperationCount,
		OtherOperations:   accounting.io.OtherOperationCount,
		ReadBytes:         accounting.io.ReadTransferCount,
		WriteBytes:        accounting.io.WriteTransferCount,
		OtherBytes:        accounting.io.OtherTransferCount,
		Measured:          true,
	}
}

func queryAccounting(job windows.Handle, accounting *jobBasicAndIOAccounting) error {
	return windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAndIoAccountingInformation,
		uintptr(nativePointer(accounting)),
		uint32(unsafe.Sizeof(*accounting)),
		nil,
	)
}

func queryLimits(job windows.Handle, limits *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
	return windows.QueryInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(nativePointer(limits)),
		uint32(unsafe.Sizeof(*limits)),
		nil,
	)
}

func processPeakWorkingSet(process windows.Handle) (uint64, error) {
	return processPeakWorkingSetWith(process, func(
		handle windows.Handle,
		counters *processMemoryCounters,
	) error {
		result, _, callErr := getProcessMemoryInfo.Call(
			uintptr(handle),
			uintptr(nativePointer(counters)),
			uintptr(counters.size),
		)
		if result != 0 {
			return nil
		}
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return callErr
		}
		return errors.New("GetProcessMemoryInfo failed")
	})
}

func processPeakWorkingSetWith(
	process windows.Handle,
	query func(windows.Handle, *processMemoryCounters) error,
) (uint64, error) {
	counters := processMemoryCounters{size: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	if err := query(process, &counters); err != nil {
		return 0, err
	}
	return uint64(counters.peakWorkingSet), nil
}

func windowsTicks(user, kernel int64) time.Duration {
	const maximum = int64(^uint64(0) >> 1)
	if user < 0 || kernel < 0 || user > maximum-kernel ||
		user+kernel > maximum/100 {
		return time.Duration(maximum)
	}
	return time.Duration((user + kernel) * 100)
}
