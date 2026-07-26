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

package attemptstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

func writeRecord(path, name string, value any) (err error) {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxRecordBytes {
		return fmt.Errorf("%w: record exceeds limit", ErrInvalid)
	}
	temporary, err := createRecordTemp(path, name)
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		removeErr := os.Remove(temporaryName)
		if !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	target := filepath.Join(path, name)
	if _, err := os.Stat(target); err == nil {
		return ErrDuplicate
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := publishFile(temporaryName, target, path); err != nil {
		return err
	}
	return nil
}

func writeOrMatchRecord(path, name string, value any) error {
	err := writeRecord(path, name, value)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrDuplicate) {
		return err
	}
	existing := reflect.New(reflect.TypeOf(value)).Interface()
	if readErr := readRecord(path, name, existing); readErr != nil {
		return readErr
	}
	if !reflect.DeepEqual(reflect.ValueOf(existing).Elem().Interface(), value) {
		return ErrDuplicate
	}
	return confirmPublication(path)
}

func readRecord(path, name string, target any) error {
	data, err := readRooted(path, name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if err := requireRecordFields(data, target); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrCorrupt
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrCorrupt
	}
	return validateRecord(target)
}

func verifyHash(path, name, expected string) error {
	actual, err := fileHash(path, name)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrCorrupt
	}
	return nil
}

func fileHash(path, name string) (string, error) {
	data, err := readRooted(path, name)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func readRooted(path, name string) (data []byte, err error) {
	if err := rejectLinkedAncestors(path); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if invalidRecordFile(filepath.Join(path, name), info) {
		return nil, ErrCorrupt
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if invalidRecordFile(filepath.Join(path, name), info) {
		return nil, ErrCorrupt
	}
	data, err = io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, ErrCorrupt
	}
	return data, nil
}
