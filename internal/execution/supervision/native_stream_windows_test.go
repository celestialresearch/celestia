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
	"os"

	"strings"
	"testing"
	"time"
)

func TestStreamAndInputCancellationReportCloseFailures(t *testing.T) {
	t.Run("wrapped input", func(t *testing.T) {
		file := closedTemporaryFile(t)
		writer := &inputWriter{file: file, done: make(chan struct{})}
		if err := writer.cancel(); err == nil {
			t.Fatal("closed input file was reported closed")
		}
	})
	t.Run("wrapped stream", func(t *testing.T) {
		file := closedTemporaryFile(t)
		reader := &streamReader{
			name: "output", file: file, done: make(chan struct{}),
		}
		if err := reader.cancel(); err == nil {
			t.Fatal("closed stream file was reported closed")
		}
	})
}

func TestCancelIO(t *testing.T) {
	failure := windows.ERROR_INVALID_HANDLE
	tests := []struct {
		name      string
		handle    windows.Handle
		cancelErr error
		wantCall  bool
		wantErr   bool
	}{
		{name: "empty handle"},
		{name: "invalid handle", handle: windows.InvalidHandle},
		{name: "success", handle: 1, wantCall: true},
		{
			name: "completed operation", handle: 1,
			cancelErr: windows.ERROR_NOT_FOUND, wantCall: true,
		},
		{
			name: "cancellation failure", handle: 1,
			cancelErr: failure, wantCall: true, wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := cancelIOWith(
				test.handle,
				"output",
				func(handle windows.Handle, overlapped *windows.Overlapped) error {
					called = true
					if handle != test.handle || overlapped != nil {
						t.Fatalf("handle=%d overlapped=%v", handle, overlapped)
					}
					return test.cancelErr
				},
			)
			if called != test.wantCall {
				t.Fatalf("called=%t, want %t", called, test.wantCall)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v, want error=%t", err, test.wantErr)
			}
			if test.wantErr && !errors.Is(err, failure) {
				t.Fatalf("error=%v, want %v", err, failure)
			}
		})
	}
}

func TestStreamAndInputJoinPreserveCancellationFailure(t *testing.T) {
	deadline := time.Now().Add(-time.Second)
	t.Run("input", func(t *testing.T) {
		writer := &inputWriter{
			file: closedTemporaryFile(t), done: make(chan struct{}),
		}
		result := awaitInput(
			writer,
			deadline,
			deadline,
		)
		if result.joinErr == nil ||
			!strings.Contains(result.joinErr.Error(), "cleanup deadline exceeded") {
			t.Fatalf("join failure lost: %v", result.joinErr)
		}
	})
	t.Run("stream", func(t *testing.T) {
		reader := &streamReader{
			name: "output", file: closedTemporaryFile(t),
			done: make(chan struct{}),
		}
		result := awaitStream(
			reader,
			make(chan streamResult),
			deadline,
			deadline,
		)
		if result.cleanupErr == nil ||
			!strings.Contains(result.cleanupErr.Error(), "close worker output") {
			t.Fatalf("cleanup failure lost: %v", result.cleanupErr)
		}
	})
}

func closedTemporaryFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatalf("create temporary file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary file: %v", err)
	}
	return file
}
