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
)

type jobAccounting struct {
	_               int64
	_               int64
	_               int64
	_               int64
	_               uint32
	_               uint32
	activeProcesses uint32
	_               uint32
}

func cleanupSucceeded(previous bool, err error) bool {
	return previous && err == nil
}

func (resources *launchResources) close() error {
	closeErr := resources.pipes.close()
	if resources.job != 0 {
		closeErr = errors.Join(closeErr, windows.CloseHandle(resources.job))
	}
	if resources.image != nil {
		closeErr = errors.Join(closeErr, resources.image.Close())
	}
	closeErr = errors.Join(closeErr, resources.container.close())
	return closeErr
}

func (process *launchedProcess) close() error {
	closeErr := process.pipes.close()
	if err := windows.CloseHandle(process.info.Thread); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker thread: %w", err))
	}
	if err := windows.CloseHandle(process.info.Process); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker process: %w", err))
	}
	if err := windows.CloseHandle(process.job); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker job: %w", err))
	}
	if err := process.image.Close(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker image: %w", err))
	}
	if err := process.container.close(); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	return closeErr
}
