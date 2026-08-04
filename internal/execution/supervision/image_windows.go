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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type imageStageOperations struct {
	mkdir      func(string, fs.FileMode) error
	openSource func(string) (*os.File, error)
	openStage  func(string, uint32, uint32) (*os.File, error)
	copy       func(io.Writer, io.Reader) (int64, error)
	sync       func(*os.File) error
	close      func(*os.File) error
	verify     func(*os.File, [32]byte) error
}

type lockedFileOperations struct {
	encode      func(string) (*uint16, error)
	create      func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error)
	information func(windows.Handle, *windows.ByHandleFileInformation) error
	newFile     func(uintptr, string) *os.File
	close       func(windows.Handle) error
}

func stageImage(
	folder,
	source string,
) (image *os.File, hash [32]byte, path string, cleanupComplete bool, err error) {
	return stageImageWith(folder, source, defaultImageStageOperations())
}

func defaultImageStageOperations() imageStageOperations {
	return imageStageOperations{
		mkdir:      os.MkdirAll,
		openSource: openLocalImage,
		openStage:  openLocked,
		copy:       io.Copy,
		sync:       (*os.File).Sync,
		close:      (*os.File).Close,
		verify:     verifyImage,
	}
}

func stageImageWith(
	folder, source string,
	operations imageStageOperations,
) (image *os.File, hash [32]byte, path string, cleanupComplete bool, err error) {
	cleanupComplete = true
	var sourceFile *os.File
	var writer *os.File
	defer func() {
		if err == nil {
			return
		}
		closeErr := closeFilesWith(operations.close, image, writer, sourceFile)
		cleanupComplete = cleanupComplete && closeErr == nil
		err = errors.Join(err, closeErr)
		image = nil
	}()
	if err := operations.mkdir(folder, 0o700); err != nil {
		return nil, hash, "", true, fmt.Errorf("prepare AppContainer folder: %w", err)
	}
	sourceFile, err = operations.openSource(source)
	if err != nil {
		return nil, hash, "", true, fmt.Errorf("open worker: %w", err)
	}
	path = filepath.Join(folder, "worker.exe")
	writer, err = operations.openStage(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.CREATE_NEW,
	)
	if err != nil {
		return nil, hash, "", true, fmt.Errorf("create staged worker: %w", err)
	}
	digest := sha256.New()
	if _, err := operations.copy(io.MultiWriter(writer, digest), sourceFile); err != nil {
		return nil, hash, "", true, fmt.Errorf("stage worker: %w", err)
	}
	if err := operations.sync(writer); err != nil {
		return nil, hash, "", true, fmt.Errorf("flush staged worker: %w", err)
	}
	if err := operations.close(writer); err != nil {
		return nil, hash, "", false, fmt.Errorf("close staged worker: %w", err)
	}
	writer = nil
	image, err = operations.openStage(
		path,
		windows.GENERIC_READ,
		windows.OPEN_EXISTING,
	)
	if err != nil {
		path = ""
		err = fmt.Errorf("lock staged worker: %w", err)
		return
	}
	copy(hash[:], digest.Sum(nil))
	if verifyErr := operations.verify(image, hash); verifyErr != nil {
		path = ""
		err = verifyErr
		return
	}
	if closeErr := operations.close(sourceFile); closeErr != nil {
		path = ""
		cleanupComplete = false
		err = fmt.Errorf("close worker source: %w", closeErr)
		return
	}
	sourceFile = nil
	return image, hash, path, true, nil
}

func closeFilesWith(close func(*os.File) error, files ...*os.File) error {
	var closeErr error
	for _, file := range files {
		if file != nil {
			closeErr = errors.Join(closeErr, close(file))
		}
	}
	return closeErr
}

func verifyImage(image *os.File, expected [32]byte) error {
	return verifyImageWith(expected, func() ([32]byte, error) {
		return hashFile(image)
	})
}

func verifyImageWith(expected [32]byte, hash func() ([32]byte, error)) error {
	actual, err := hash()
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("staged worker changed before execution lock")
	}
	return nil
}

func hashFile(file *os.File) ([32]byte, error) {
	return hashFileWith(file, (*os.File).Seek, io.Copy)
}

func hashFileWith(
	file *os.File,
	seek func(*os.File, int64, int) (int64, error),
	copyFile func(io.Writer, io.Reader) (int64, error),
) ([32]byte, error) {
	var result [32]byte
	if _, err := seek(file, 0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind staged worker: %w", err)
	}
	digest := sha256.New()
	if _, err := copyFile(digest, file); err != nil {
		return result, fmt.Errorf("hash staged worker: %w", err)
	}
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func openLocked(path string, access, disposition uint32) (*os.File, error) {
	return openLockedWith(path, access, disposition, lockedFileOperations{
		encode:      windows.UTF16PtrFromString,
		create:      windows.CreateFile,
		information: windows.GetFileInformationByHandle,
		newFile:     os.NewFile,
		close:       windows.CloseHandle,
	})
}

func openLockedWith(
	path string,
	access, disposition uint32,
	operations lockedFileOperations,
) (*os.File, error) {
	pointer, err := operations.encode(path)
	if err != nil {
		return nil, err
	}
	handle, err := operations.create(
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
	if err := operations.information(handle, &information); err != nil {
		return nil, errors.Join(err, operations.close(handle))
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.Join(
			errors.New("worker must be a regular non-reparse file"),
			operations.close(handle),
		)
	}
	file := operations.newFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.Join(errors.New("create worker file"), operations.close(handle))
	}
	return file, nil
}

func openLocalImage(path string) (*os.File, error) {
	return openLocalImageWith(path, openLocked, validateLocalImage)
}

func openLocalImageWith(
	path string,
	open func(string, uint32, uint32) (*os.File, error),
	validate func(*os.File, string) error,
) (*os.File, error) {
	file, err := open(path, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, err
	}
	if err := validate(file, path); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func validateLocalImage(file *os.File, configuredPath string) error {
	return validateLocalImageWith(
		configuredPath,
		windows.Handle(file.Fd()),
		workerDriveType,
		finalImagePath,
	)
}

func validateLocalImageWith(
	configuredPath string,
	handle windows.Handle,
	driveType func(string) (uint32, error),
	resolve func(windows.Handle) (string, error),
) error {
	configuredType, err := driveType(configuredPath)
	if err != nil || configuredType == windows.DRIVE_REMOTE {
		return errors.Join(errors.New("worker must use a local volume"), err)
	}
	finalPath, err := resolve(handle)
	if err != nil {
		return err
	}
	finalType, err := driveType(strings.TrimPrefix(finalPath, `\\?\`))
	if err != nil || !validLocalFinalPath(finalPath, finalType) {
		return errors.Join(errors.New("worker resolved outside a local volume"), err)
	}
	return nil
}

func workerDriveType(path string) (uint32, error) {
	return workerDriveTypeWith(path, windows.GetDriveType)
}

func workerDriveTypeWith(path string, getDriveType func(*uint16) uint32) (uint32, error) {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return windows.DRIVE_UNKNOWN, errors.New("worker volume is not a drive letter")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return windows.DRIVE_UNKNOWN, err
	}
	driveType := getDriveType(root)
	if driveType == windows.DRIVE_UNKNOWN || driveType == windows.DRIVE_NO_ROOT_DIR {
		return driveType, errors.New("worker volume is unavailable")
	}
	return driveType, nil
}

func finalImagePath(handle windows.Handle) (string, error) {
	return finalImagePathWith(handle, windows.GetFinalPathNameByHandle)
}

func finalImagePathWith(
	handle windows.Handle,
	resolve func(windows.Handle, *uint16, uint32, uint32) (uint32, error),
) (string, error) {
	size := uint32(512)
	for range 2 {
		buffer := make([]uint16, size)
		length, err := resolve(handle, &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if length < size {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		size = length
	}
	return "", errors.New("resolved worker path exceeds reported size")
}

func validLocalFinalPath(path string, driveType uint32) bool {
	if driveType == windows.DRIVE_REMOTE {
		return false
	}
	const prefix = `\\?\`
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	resolved := strings.TrimPrefix(path, prefix)
	return validWorkerPath(resolved)
}
