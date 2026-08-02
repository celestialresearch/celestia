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
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

func sourceFiles() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx, "git", "ls-files", "-co", "--exclude-standard", "-z",
	)
	return inventorySourceFiles(command, cancel)
}

type inventoryCommand interface {
	Start() error
	StdoutPipe() (io.ReadCloser, error)
	Wait() error
}

func inventorySourceFiles(
	command inventoryCommand,
	cancel context.CancelFunc,
) ([]string, error) {
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("inventory source files: %w", err)
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("inventory source files: %w", err)
	}
	files, readErr := readInventory(output)
	if readErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("inventory source files: %w", readErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("inventory source files: %w", waitErr)
	}
	return files, nil
}

func readInventory(source io.Reader) ([]string, error) {
	return readInventoryWithLimits(
		source,
		maxInventoryBytes,
		maxInventoryPaths,
		maxInventoryPathBytes,
	)
}

func readInventoryWithLimits(
	source io.Reader,
	maxBytes, maxPaths, maxPathBytes int,
) ([]string, error) {
	reader := bufio.NewReaderSize(source, maxPathBytes+1)
	files := make([]string, 0, 256)
	total := 0
	for {
		path, err := reader.ReadSlice(0)
		total += len(path)
		if total > maxBytes {
			return nil, errors.New("source inventory exceeds the byte limit")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("source inventory path exceeds the size limit")
		}
		if err == nil && len(path)-1 > maxPathBytes {
			return nil, errors.New("source inventory path exceeds the size limit")
		}
		if errors.Is(err, io.EOF) {
			if len(path) != 0 {
				return nil, errors.New("source inventory is not NUL terminated")
			}
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		path = path[:len(path)-1]
		if len(path) == 0 {
			return nil, errors.New("source inventory contains an empty path")
		}
		if len(files) == maxPaths {
			return nil, errors.New("source inventory exceeds the path limit")
		}
		files = append(files, string(path))
	}
}
