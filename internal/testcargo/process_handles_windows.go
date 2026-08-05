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

package testcargo

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

type jobProcessIDList struct {
	assigned uint32
	count    uint32
	ids      [1]uintptr
}

func jobProcessHandles(job windows.Handle) ([]windows.Handle, error) {
	size, err := nextProcessListSize(0, 16, 0)
	if err != nil {
		return nil, err
	}
	for {
		buffer := make([]byte, size)
		err := windows.QueryInformationJobObject(
			job,
			windows.JobObjectBasicProcessIdList,
			uintptr(nativePointer(&buffer[0])),
			size,
			nil,
		)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("query terminated Cargo process tree: %w", err)
		}
		list := (*jobProcessIDList)(nativePointer(&buffer[0]))
		nextSize, sizeErr := nextProcessListSize(size, list.assigned, list.count)
		if sizeErr != nil {
			return nil, sizeErr
		}
		if nextSize != 0 {
			size = nextSize
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("query terminated Cargo process tree: %w", err)
		}
		available := (size - uint32(unsafe.Offsetof(jobProcessIDList{}.ids))) / uint32(unsafe.Sizeof(uintptr(0)))
		if list.count > available {
			return nil, errors.New("query terminated Cargo process tree: invalid process count")
		}
		return openJobProcesses(job, processIDs(list))
	}
}

func openJobProcesses(job windows.Handle, ids []uintptr) ([]windows.Handle, error) {
	handles := make([]windows.Handle, 0, len(ids))
	for _, id := range ids {
		if id > uintptr(^uint32(0)) {
			return nil, errors.New("query terminated Cargo process tree: invalid process identity")
		}
		handle, err := windows.OpenProcess(
			windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
			false,
			uint32(id),
		)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			continue
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("open terminated Cargo process: %w", err), closeProcessHandles(handles))
		}
		member, err := processBelongsToJob(handle, job)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("validate terminated Cargo process: %w", err),
				closeHandle("close unrelated Cargo process", handle),
				closeProcessHandles(handles),
			)
		}
		if !member {
			if err := closeHandle("close unrelated Cargo process", handle); err != nil {
				return nil, errors.Join(err, closeProcessHandles(handles))
			}
			continue
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func processBelongsToJob(process, job windows.Handle) (bool, error) {
	var member int32
	result, _, callErr := isProcessInJob.Call(
		uintptr(process),
		uintptr(job),
		uintptr(nativePointer(&member)),
	)
	if result != 0 {
		return member != 0, nil
	}
	if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
		return false, callErr
	}
	return false, errors.New("IsProcessInJob failed")
}

func nextProcessListSize(current, assigned, count uint32) (uint32, error) {
	if count > assigned {
		return 0, errors.New("query terminated Cargo process tree: invalid process count")
	}
	if count == assigned && current != 0 {
		return 0, nil
	}
	required := uint64(unsafe.Offsetof(jobProcessIDList{}.ids)) + uint64(assigned)*uint64(unsafe.Sizeof(uintptr(0)))
	if required > 1<<20 || required > uint64(^uint32(0)) {
		return 0, errors.New("query terminated Cargo process tree: process list is too large")
	}
	if uint32(required) <= current {
		return 0, errors.New("query terminated Cargo process tree: incomplete process list")
	}
	return uint32(required), nil
}

func processIDs(list *jobProcessIDList) []uintptr {
	return unsafe.Slice(&list.ids[0], list.count) // #nosec G103 -- Win32 supplies the bounded variable-length process list.
}

func closeProcessHandles(handles []windows.Handle) error {
	var result error
	for _, handle := range handles {
		result = errors.Join(result, closeHandle("close terminated Cargo process", handle))
	}
	return result
}
