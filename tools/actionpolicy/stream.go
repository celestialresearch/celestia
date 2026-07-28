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
	"bufio"
	"errors"
	"fmt"
	"io"
)

type streamLimits struct {
	documents  int
	pathBytes  int
	dataBytes  int
	totalBytes int
}

func inspectDocuments(input io.Reader, output io.Writer, mode string, limits streamLimits) error {
	if !validStreamLimits(limits) {
		return errors.New("action document limits must be positive")
	}

	reader := bufio.NewReader(input)
	total := 0
	var failures []error
	for count := 0; ; count++ {
		path, done, err := readField(reader, limits.pathBytes, true)
		if err != nil {
			return fmt.Errorf("read action path: %w", err)
		}
		if done {
			return errors.Join(failures...)
		}
		if count >= limits.documents {
			return errors.New("action document count exceeds limit")
		}
		if err := validateDocumentPath(path); err != nil {
			return err
		}
		data, done, err := readField(reader, limits.dataBytes, true)
		if err != nil {
			return fmt.Errorf("%s: read action document: %w", path, err)
		}
		if done {
			return fmt.Errorf("%s: action document is missing", path)
		}
		total += len(path) + len(data)
		if total > limits.totalBytes {
			return errors.New("action document corpus exceeds limit")
		}
		if err := inspect(document{path: string(path), data: data}, mode, output); err != nil {
			failures = append(failures, err)
		}
	}
}

func validStreamLimits(limits streamLimits) bool {
	return limits.documents > 0 && limits.pathBytes > 0 &&
		limits.dataBytes > 0 && limits.totalBytes > 0
}

func readField(reader *bufio.Reader, limit int, cleanEOF bool) ([]byte, bool, error) {
	value := make([]byte, 0, min(limit, bufio.MaxScanTokenSize))
	for {
		fragment, err := reader.ReadSlice(0)
		delimited := err == nil
		length := len(value) + len(fragment)
		if delimited {
			length--
		}
		if length > limit {
			return nil, false, errors.New("field exceeds limit")
		}
		if delimited {
			value = append(value, fragment[:len(fragment)-1]...)
			if len(value) == 0 {
				return nil, false, errors.New("field is empty")
			}
			return value, false, nil
		}
		value = append(value, fragment...)
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && cleanEOF && len(value) == 0:
			return nil, true, nil
		case errors.Is(err, io.EOF):
			return nil, false, errors.New("field is truncated")
		default:
			return nil, false, err
		}
	}
}
