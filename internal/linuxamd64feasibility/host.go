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

package linuxamd64feasibility

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

func readCgroupFile() ([]byte, error) {
	file, err := os.Open(controllersPath)
	if err != nil {
		return nil, err
	}
	data, readErr := readBounded(file)
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	return data, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(reader, maxCgroupBytes+1))
}

func lstatMode(name string) (fs.FileMode, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return 0, err
	}
	return info.Mode(), nil
}
