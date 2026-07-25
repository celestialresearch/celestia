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

//go:build windows

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
	defer func() {
		_ = reader.cancel()
		close(reader.done)
	}()
	if reader.file == nil {
		result <- streamResult{err: errors.New("create worker stream")}
		return
	}
	var buffer bytes.Buffer
	_, err := io.CopyN(&buffer, reader.file, int64(limit)+1)
	if err == nil || buffer.Len() > limit {
		select {
		case overflow <- overflowStatus:
		default:
		}
		result <- streamResult{
			data: buffer.Bytes()[:min(buffer.Len(), limit)],
			err:  errStreamLimit,
		}
		return
	}
	if !errors.Is(err, io.EOF) {
		result <- streamResult{data: buffer.Bytes(), err: err}
		return
	}
	result <- streamResult{data: buffer.Bytes()}
}

func (reader *streamReader) cancel() error {
	reader.close.Do(func() {
		if reader.handle != 0 && reader.handle != windows.InvalidHandle {
			if err := windows.CancelIoEx(reader.handle, nil); err != nil &&
				!errors.Is(err, windows.ERROR_NOT_FOUND) {
				reader.closeErr = fmt.Errorf("cancel worker %s I/O: %w", reader.name, err)
			}
		}
		if reader.file != nil {
			if err := reader.file.Close(); err != nil {
				reader.closeErr = errors.Join(reader.closeErr, err)
			}
		}
	})
	return reader.closeErr
}

func awaitStream(
	reader *streamReader,
	result <-chan streamResult,
	deadline time.Time,
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
		err := fmt.Errorf("join worker %s: cleanup deadline exceeded", reader.name)
		if closeErr := reader.cancel(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close worker %s: %w", reader.name, closeErr))
		}
		joinTimer := time.NewTimer(100 * time.Millisecond)
		defer joinTimer.Stop()
		select {
		case <-reader.done:
			value := <-result
			value.err = errors.Join(err, value.err)
			return value
		case <-joinTimer.C:
			return streamResult{err: err}
		}
	}
}
