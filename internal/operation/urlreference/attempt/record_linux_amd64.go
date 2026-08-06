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

package attemptstore

import (
	"errors"
	"os"
)

func createRecordTemp(path, name string) (file *os.File, err error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := root.Close()
		if closeErr != nil && file != nil {
			closeErr = errors.Join(closeErr, file.Close())
			file = nil
		}
		err = errors.Join(err, closeErr)
	}()
	for range 8 {
		temporary, err := recordTempName(name)
		if err != nil {
			return nil, err
		}
		file, err = root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return file, err
	}
	return nil, errors.New("create unique record file")
}
