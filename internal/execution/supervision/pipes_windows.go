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
	"golang.org/x/sys/windows"
	"unsafe"
)

type pipeSet struct {
	stdinRead   windows.Handle
	stdinWrite  windows.Handle
	stdoutRead  windows.Handle
	stdoutWrite windows.Handle
	stderrRead  windows.Handle
	stderrWrite windows.Handle
}

func newPipes() (pipeSet, bool, error) {
	return newPipesWith(windows.CreatePipe, windows.SetHandleInformation)
}

func newPipesWith(
	create func(*windows.Handle, *windows.Handle, *windows.SecurityAttributes, uint32) error,
	restrict func(windows.Handle, uint32, uint32) error,
) (pipeSet, bool, error) {
	var pipes pipeSet
	security := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	if err := create(&pipes.stdinRead, &pipes.stdinWrite, &security, 0); err != nil {
		return pipes, true, fmt.Errorf("create stdin pipe: %w", err)
	}
	if err := create(&pipes.stdoutRead, &pipes.stdoutWrite, &security, 0); err != nil {
		return failedPipes(pipes, fmt.Errorf("create stdout pipe: %w", err))
	}
	if err := create(&pipes.stderrRead, &pipes.stderrWrite, &security, 0); err != nil {
		return failedPipes(pipes, fmt.Errorf("create stderr pipe: %w", err))
	}
	for _, handle := range []windows.Handle{pipes.stdinWrite, pipes.stdoutRead, pipes.stderrRead} {
		if err := restrict(handle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			return failedPipes(pipes, fmt.Errorf("restrict parent pipe: %w", err))
		}
	}
	return pipes, true, nil
}

func failedPipes(pipes pipeSet, operationErr error) (pipeSet, bool, error) {
	closeErr := pipes.close()
	return pipes, closeErr == nil, errors.Join(operationErr, closeErr)
}
