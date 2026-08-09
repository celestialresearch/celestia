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

package attempt

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func (s *Store) writeRecord(name string, data []byte) error {
	if filepath.Base(name) != name || name == "" {
		return ErrCorrupt
	}
	match, err := s.recordMatches(name, data)
	if err != nil {
		return err
	}
	if match {
		return errors.Join(syncDirectory(s.directory), s.faults.directorySync)
	}
	staging := "." + name + ".publishing"
	if err := s.prepareStaging(staging, data); err != nil {
		return err
	}
	if err := s.writeStaging(staging, data); err != nil {
		return err
	}
	if err := s.publishStaging(staging, name, data); err != nil {
		return err
	}
	return errors.Join(syncDirectory(s.directory), s.faults.directorySync)
}

func (s *Store) writeStaging(staging string, data []byte) error {
	file, err := s.root.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeData := data
	if s.faults.shortWrite && len(writeData) != 0 {
		writeData = writeData[:len(writeData)-1]
	}
	written, writeErr := file.Write(writeData)
	writeErr = errors.Join(writeErr, s.faults.write)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := errors.Join(file.Sync(), s.faults.sync)
	closeErr := errors.Join(file.Close(), s.faults.close)
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return nil
}

func (s *Store) publishStaging(staging, name string, data []byte) error {
	if s.faults.publish != nil {
		return s.faults.publish
	}
	stagingPath := filepath.Join(s.path, staging)
	finalPath := filepath.Join(s.path, name)
	stagingPointer, stagingErr := windows.UTF16PtrFromString(stagingPath)
	finalPointer, finalErr := windows.UTF16PtrFromString(finalPath)
	if err := errors.Join(stagingErr, finalErr); err != nil {
		return err
	}
	if err := windows.MoveFile(stagingPointer, finalPointer); err != nil {
		match, matchErr := s.recordMatches(name, data)
		if matchErr != nil || !match {
			return errors.Join(err, matchErr)
		}
		if removeErr := s.root.Remove(staging); removeErr != nil &&
			!errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	return nil
}

func (s *Store) prepareStaging(name string, data []byte) error {
	_, err := s.recordMatches(name, data)
	if err != nil && !errors.Is(err, ErrDuplicate) {
		return err
	}
	if err := s.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.directory)
}

func (s *Store) recordMatches(name string, expected []byte) (bool, error) {
	file, err := s.root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := secureRecordHandle(file); err != nil {
		return false, errors.Join(ErrCorrupt, err, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return false, err
	}
	if bytes.Equal(data, expected) {
		return true, nil
	}
	return false, ErrDuplicate
}
