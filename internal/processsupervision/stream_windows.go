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
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

type streamReader struct {
	name     string
	handle   windows.Handle
	file     *os.File
	done     chan struct{}
	close    sync.Once
	closeErr error
}

func (pipes *pipeSet) closeChildEnds() error {
	return errors.Join(
		closeHandle(&pipes.stdinRead),
		closeHandle(&pipes.stdoutWrite),
		closeHandle(&pipes.stderrWrite),
	)
}

func (pipes *pipeSet) close() error {
	return errors.Join(
		closeHandle(&pipes.stdinRead),
		closeHandle(&pipes.stdinWrite),
		closeHandle(&pipes.stdoutRead),
		closeHandle(&pipes.stdoutWrite),
		closeHandle(&pipes.stderrRead),
		closeHandle(&pipes.stderrWrite),
	)
}

func closeHandle(handle *windows.Handle) error {
	if *handle == 0 {
		return nil
	}
	err := windows.CloseHandle(*handle)
	if err == nil {
		*handle = 0
	}
	return err
}

func newStreamReader(name string, handle windows.Handle) *streamReader {
	return &streamReader{
		name:   name,
		handle: handle,
		done:   make(chan struct{}),
		file: os.NewFile(
			uintptr(handle),
			"worker-"+name,
		),
	}
}

func (reader *streamReader) read(
	limit int,
	overflowStatus Status,
	result chan<- streamResult,
	overflow chan<- Status,
) {
	value := reader.readResult(limit, overflowStatus, overflow)
	value.cleanupErr = reader.cancel()
	result <- value
	close(reader.done)
}

func (reader *streamReader) readResult(
	limit int,
	overflowStatus Status,
	overflow chan<- Status,
) streamResult {
	if reader.file == nil {
		return streamResult{err: errors.New("create worker stream")}
	}
	var buffer bytes.Buffer
	_, err := io.CopyN(&buffer, reader.file, int64(limit)+1)
	if err == nil {
		select {
		case overflow <- overflowStatus:
		default:
		}
		return streamResult{
			data: buffer.Bytes()[:min(buffer.Len(), limit)],
			err:  errStreamLimit,
		}
	}
	if !errors.Is(err, io.EOF) {
		return streamResult{data: buffer.Bytes(), err: err}
	}
	return streamResult{data: buffer.Bytes()}
}

func (reader *streamReader) cancel() error {
	reader.close.Do(func() {
		reader.closeErr = cancelIO(reader.handle, reader.name)
		if reader.file != nil {
			if err := reader.file.Close(); err != nil {
				reader.closeErr = errors.Join(reader.closeErr, err)
			}
		}
	})
	return reader.closeErr
}

func cancelIO(handle windows.Handle, name string) error {
	return cancelIOWith(handle, name, windows.CancelIoEx)
}

func cancelIOWith(
	handle windows.Handle,
	name string,
	cancel func(windows.Handle, *windows.Overlapped) error,
) error {
	if handle == 0 || handle == windows.InvalidHandle {
		return nil
	}
	if err := cancel(handle, nil); err != nil &&
		!errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("cancel worker %s I/O: %w", name, err)
	}
	return nil
}

func awaitStream(
	reader *streamReader,
	result <-chan streamResult,
	deadline time.Time,
	joinDeadline time.Time,
) streamResult {
	select {
	case value := <-result:
		return value
	default:
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		timeout = time.Nanosecond
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-result:
		return value
	case <-timer.C:
		cleanupErr := fmt.Errorf("join worker %s: cleanup deadline exceeded", reader.name)
		if closeErr := reader.cancel(); closeErr != nil {
			cleanupErr = errors.Join(
				cleanupErr,
				fmt.Errorf("close worker %s: %w", reader.name, closeErr),
			)
		}
		joinTimer := time.NewTimer(cleanupRemaining(joinDeadline))
		defer joinTimer.Stop()
		select {
		case <-reader.done:
			value := <-result
			value.cleanupErr = errors.Join(cleanupErr, value.cleanupErr)
			return value
		case <-joinTimer.C:
			return streamResult{cleanupErr: cleanupErr}
		}
	}
}
