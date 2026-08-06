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

//go:build linux && amd64

package linuxamd64feasibility

import (
	"bytes"
	"errors"
	"io"
	"os"
)

func durabilityMount(target string) (mountEntry, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return mountEntry{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxMountinfoBytes+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return mountEntry{}, err
	}
	if len(data) > maxMountinfoBytes {
		return mountEntry{}, errDurabilityMountMismatch
	}
	return mountedFilesystemEntry(bytes.NewReader(data), target)
}
