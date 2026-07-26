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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func stageImage(
	folder,
	source string,
) (image *os.File, hash [32]byte, path string, cleanupComplete bool, err error) {
	cleanupComplete = true
	var sourceFile *os.File
	var writer *os.File
	defer func() {
		if err == nil {
			return
		}
		closeErr := closeFiles(image, writer, sourceFile)
		cleanupComplete = cleanupComplete && closeErr == nil
		err = errors.Join(err, closeErr)
		image = nil
	}()
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return nil, hash, "", true, fmt.Errorf("prepare AppContainer folder: %w", err)
	}
	sourceFile, err = openLocked(source, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, hash, "", true, fmt.Errorf("open worker: %w", err)
	}
	path = filepath.Join(folder, "worker.exe")
	writer, err = openLocked(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.CREATE_NEW)
	if err != nil {
		return nil, hash, "", true, fmt.Errorf("create staged worker: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(writer, digest), sourceFile); err != nil {
		return nil, hash, "", true, fmt.Errorf("stage worker: %w", err)
	}
	if err := writer.Sync(); err != nil {
		return nil, hash, "", true, fmt.Errorf("flush staged worker: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, hash, "", false, fmt.Errorf("close staged worker: %w", err)
	}
	writer = nil
	image, err = openLocked(path, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, hash, "", true, fmt.Errorf("lock staged worker: %w", err)
	}
	copy(hash[:], digest.Sum(nil))
	if err := verifyImage(image, hash); err != nil {
		return nil, hash, "", true, err
	}
	if err := sourceFile.Close(); err != nil {
		return nil, hash, "", false, fmt.Errorf("close worker source: %w", err)
	}
	sourceFile = nil
	return image, hash, path, true, nil
}

func closeFiles(files ...*os.File) error {
	var closeErr error
	for _, file := range files {
		if file != nil {
			closeErr = errors.Join(closeErr, file.Close())
		}
	}
	return closeErr
}

func verifyImage(image *os.File, expected [32]byte) error {
	actual, err := hashFile(image)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("staged worker changed before execution lock")
	}
	return nil
}

func hashFile(file *os.File) ([32]byte, error) {
	var result [32]byte
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind staged worker: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return result, fmt.Errorf("hash staged worker: %w", err)
	}
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func openLocked(path string, access, disposition uint32) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer,
		access,
		windows.FILE_SHARE_READ,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return nil, errors.Join(err, windows.CloseHandle(handle))
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.Join(
			errors.New("worker must be a regular non-reparse file"),
			windows.CloseHandle(handle),
		)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.Join(errors.New("create worker file"), windows.CloseHandle(handle))
	}
	return file, nil
}
