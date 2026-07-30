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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package attemptstore

import (
	"errors"
	"os"
)

func createRecordTemp(path, name string) (*os.File, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	file, createErr := createRecordTempAt(root, name)
	closeErr := root.Close()
	if closeErr != nil {
		if file != nil {
			closeErr = errors.Join(closeErr, file.Close())
		}
		return nil, errors.Join(createErr, closeErr)
	}
	return file, createErr
}

func createRecordTempAt(root *os.Root, name string) (*os.File, error) {
	for range 8 {
		temporaryName, err := recordTempName(name)
		if err != nil {
			return nil, err
		}
		file, err := root.OpenFile(
			temporaryName,
			os.O_RDWR|os.O_CREATE|os.O_EXCL,
			0o600,
		)
		if errors.Is(err, os.ErrExist) {
			if file != nil {
				if closeErr := file.Close(); closeErr != nil {
					return nil, errors.Join(err, closeErr)
				}
			}
			continue
		}
		if err != nil {
			if file != nil {
				err = errors.Join(err, file.Close())
			}
			return nil, err
		}
		return file, nil
	}
	return nil, errors.New("create unique record file")
}
