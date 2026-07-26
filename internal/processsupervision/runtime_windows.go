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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func environmentBlock(folder string) ([]uint16, error) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return nil, fmt.Errorf("%w: SystemRoot is unavailable", ErrInvalid)
	}
	temp := filepath.Join(folder, "Temp")
	if err := os.MkdirAll(temp, 0o700); err != nil {
		return nil, fmt.Errorf("prepare worker temporary directory: %w", err)
	}
	values := []string{
		"LOCALAPPDATA=" + folder,
		"SystemRoot=" + systemRoot,
		"TEMP=" + temp,
		"TMP=" + temp,
		"WINDIR=" + systemRoot,
	}
	var block []uint16
	for _, value := range values {
		encoded, err := windows.UTF16FromString(value)
		if err != nil {
			return nil, fmt.Errorf("encode worker environment: %w", err)
		}
		block = append(block, encoded...)
	}
	return append(block, 0), nil
}

func writeFrame(handle windows.Handle, frame []byte) inputResult {
	file := os.NewFile(uintptr(handle), "worker-stdin")
	if file == nil {
		return inputResult{
			err:        errors.New("create worker stdin"),
			cleanupErr: windows.CloseHandle(handle),
		}
	}
	written, writeErr := io.Copy(file, bytes.NewReader(frame))
	if writeErr == nil && written != int64(len(frame)) {
		writeErr = io.ErrShortWrite
	}
	closeErr := file.Close()
	result := inputResult{cleanupErr: closeErr}
	if writeErr != nil {
		result.err = fmt.Errorf("write worker frame: %w", writeErr)
	}
	return result
}

func waitCleanup(process, job windows.Handle, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	wait := waitMilliseconds(timeout)
	event, err := windows.WaitForSingleObject(process, wait)
	if err != nil {
		return false, fmt.Errorf("wait for worker cleanup: %w", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return false, errors.New("worker cleanup deadline exceeded")
	}
	if event != windows.WAIT_OBJECT_0 {
		return false, fmt.Errorf("unexpected worker wait result: %d", event)
	}
	for {
		empty, err := jobEmpty(job)
		if err != nil {
			return false, err
		}
		if empty {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, errors.New("process tree cleanup deadline exceeded")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitMilliseconds(timeout time.Duration) uint32 {
	milliseconds := uint64(timeout / time.Millisecond) // #nosec G115 -- valid limits require a positive duration.
	if milliseconds >= uint64(^uint32(0)-1) {
		return ^uint32(0) - 1
	}
	return uint32(milliseconds)
}

func jobEmpty(job windows.Handle) (bool, error) {
	var accounting jobAccounting
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)), // #nosec G103 -- Win32 writes the typed accounting structure.
		uint32(unsafe.Sizeof(accounting)),
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("query process tree: %w", err)
	}
	return accounting.activeProcesses == 0, nil
}
