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

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxSourceBytes = 1 << 20

func readSource(path string) (source []byte, err error) {
	return readSourceWith(path, sourceReader{
		openRoot: os.OpenRoot,
		statPath: (*os.Root).Stat,
		openFile: openSourceFile,
		stat:     (*os.File).Stat,
		read: func(reader io.Reader) ([]byte, error) {
			return io.ReadAll(io.LimitReader(reader, maxSourceBytes+1))
		},
	})
}

type sourceReader struct {
	openRoot func(string) (*os.Root, error)
	statPath func(*os.Root, string) (os.FileInfo, error)
	openFile func(*os.Root, string) (*os.File, error)
	stat     func(*os.File) (os.FileInfo, error)
	read     func(io.Reader) ([]byte, error)
}

func readSourceWith(
	path string,
	reader sourceReader,
) (source []byte, err error) {
	root, err := reader.openRoot(".")
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := root.Close(); err == nil {
			err = closeErr
		}
	}()
	name := filepath.FromSlash(path)
	info, err := reader.statPath(root, name)
	if err != nil {
		return nil, err
	}
	if err := validateSourceInfo(info); err != nil {
		return nil, err
	}
	file, err := reader.openFile(root, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	info, err = reader.stat(file)
	if err != nil {
		return nil, err
	}
	if err := validateSourceInfo(info); err != nil {
		return nil, err
	}
	if info.Size() > maxSourceBytes {
		return nil, fmt.Errorf("source file exceeds %d bytes", maxSourceBytes)
	}
	source, err = reader.read(file)
	if err != nil {
		return nil, err
	}
	if len(source) > maxSourceBytes {
		return nil, fmt.Errorf("source file exceeds %d bytes", maxSourceBytes)
	}
	return source, nil
}

func validateSourceInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return errors.New("source file is not a bounded regular file")
	}
	return nil
}
