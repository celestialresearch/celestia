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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type inputWriter struct {
	handle   windows.Handle
	file     *os.File
	done     chan struct{}
	close    sync.Once
	closeErr error
	result   inputResult
}

func environmentBlock(folder string) ([]uint16, error) {
	return environmentBlockWith(
		folder,
		windows.GetSystemWindowsDirectory,
		os.MkdirAll,
		windows.UTF16FromString,
	)
}

func environmentBlockWith(
	folder string,
	systemWindowsDirectory func() (string, error),
	mkdirAll func(string, os.FileMode) error,
	encode func(string) ([]uint16, error),
) ([]uint16, error) {
	systemRoot, err := systemWindowsDirectory()
	if err != nil {
		return nil, fmt.Errorf("find Windows directory: %w", err)
	}
	temp := filepath.Join(folder, "Temp")
	if err := mkdirAll(temp, 0o700); err != nil {
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
		encoded, err := encode(value)
		if err != nil {
			return nil, fmt.Errorf("encode worker environment: %w", err)
		}
		block = append(block, encoded...)
	}
	return append(block, 0), nil
}

func newInputWriter(handle windows.Handle) *inputWriter {
	return &inputWriter{
		handle: handle,
		file:   os.NewFile(uintptr(handle), "worker-stdin"),
		done:   make(chan struct{}),
	}
}

func (writer *inputWriter) write(frame []byte) inputResult {
	started := time.Now()
	if writer.file == nil {
		return inputResult{
			err:        errors.New("create worker stdin"),
			cleanupErr: writer.cancel(),
			duration:   time.Since(started),
		}
	}
	_, writeErr := io.Copy(writer.file, bytes.NewReader(frame))
	result := inputResult{cleanupErr: writer.cancel()}
	if writeErr != nil {
		result.err = fmt.Errorf("write worker frame: %w", writeErr)
	}
	result.duration = time.Since(started)
	return result
}

func (writer *inputWriter) publish(
	frame []byte,
	input chan<- inputResult,
) {
	writer.result = writer.write(frame)
	input <- writer.result
	close(writer.done)
}

func (writer *inputWriter) cancel() error {
	writer.close.Do(func() {
		writer.closeErr = cancelIO(writer.handle, "input")
		if writer.file != nil {
			if err := writer.file.Close(); err != nil {
				writer.closeErr = errors.Join(writer.closeErr, err)
			}
		}
	})
	return writer.closeErr
}

func awaitInput(
	writer *inputWriter,
	deadline time.Time,
	joinDeadline time.Time,
) inputResult {
	var done <-chan struct{}
	if writer != nil {
		done = writer.done
	}
	timer := time.NewTimer(cleanupRemaining(deadline))
	defer timer.Stop()
	select {
	case <-done:
		return writer.result
	case <-timer.C:
		select {
		case <-done:
			return writer.result
		default:
		}
		cleanupErr := errors.New("join worker input: cleanup deadline exceeded")
		if writer == nil {
			return inputResult{cleanupErr: cleanupErr}
		}
		if closeErr := writer.cancel(); closeErr != nil {
			cleanupErr = errors.Join(cleanupErr, closeErr)
		}
		joinTimer := time.NewTimer(cleanupRemaining(joinDeadline))
		defer joinTimer.Stop()
		select {
		case <-writer.done:
			result := writer.result
			result.joinErr = errors.Join(cleanupErr, result.joinErr)
			return result
		case <-joinTimer.C:
			return inputResult{joinErr: cleanupErr}
		}
	}
}

func waitCleanup(process, job windows.Handle, timeout time.Duration) (bool, error) {
	return waitCleanupWith(
		process,
		timeout,
		windows.WaitForSingleObject,
		func() (bool, error) {
			return jobEmpty(job)
		},
		time.Now,
		time.Sleep,
	)
}

func waitCleanupWith(
	process windows.Handle,
	timeout time.Duration,
	waitForProcess func(windows.Handle, uint32) (uint32, error),
	empty func() (bool, error),
	now func() time.Time,
	sleep func(time.Duration),
) (bool, error) {
	deadline := now().Add(timeout)
	waitMS := waitMilliseconds(timeout)
	event, err := waitForProcess(process, waitMS)
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
		if !now().Before(deadline) {
			return false, errors.New("process tree cleanup deadline exceeded")
		}
		isEmpty, err := empty()
		if err != nil {
			return false, err
		}
		if isEmpty {
			return true, nil
		}
		sleep(time.Millisecond)
	}
}

func waitMilliseconds(timeout time.Duration) uint32 {
	if timeout <= 0 {
		return 0
	}
	milliseconds := timeout / time.Millisecond
	if timeout%time.Millisecond != 0 {
		milliseconds++
	}
	const maximum = time.Duration(^uint32(0) - 1)
	if milliseconds >= maximum {
		return ^uint32(0) - 1
	}
	return uint32(milliseconds)
}

func jobEmpty(job windows.Handle) (bool, error) {
	var accounting jobAccounting
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(nativePointer(&accounting)),
		uint32(unsafe.Sizeof(accounting)),
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("query process tree: %w", err)
	}
	return accounting.activeProcesses == 0, nil
}
