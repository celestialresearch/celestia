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
	"os"
	"os/exec"
	"strings"
	"time"
)

const gitExecutableMode = "100755"

func sourceExecutables(files []string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "ls-files", "--stage", "-z")
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	executables, readErr := readExecutableInventory(output)
	if readErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return supplementExecutableInventory(files, executables, os.Lstat)
}

func supplementExecutableInventory(
	files, executables []string,
	lstat func(string) (os.FileInfo, error),
) ([]string, error) {
	declared := stringSet(executables)
	for _, file := range files {
		info, err := lstat(file)
		if err != nil {
			return nil, fmt.Errorf("inspect source %s: %w", file, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("inspect source %s: source is not a regular file", file)
		}
		_, alreadyExecutable := declared[file]
		if !alreadyExecutable && info.Mode().Perm()&0o111 != 0 {
			executables = append(executables, file)
		}
	}
	return executables, nil
}

func readExecutableInventory(source io.Reader) ([]string, error) {
	reader := bufio.NewReaderSize(source, maxInventoryPathBytes+128)
	files := make([]string, 0, 32)
	total := 0
	for {
		record, err := reader.ReadSlice(0)
		total += len(record)
		if total > maxInventoryBytes+maxInventoryPaths*128 {
			return nil, errors.New("executable inventory exceeds the byte limit")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("executable inventory path exceeds the size limit")
		}
		if errors.Is(err, io.EOF) {
			if len(record) != 0 {
				return nil, errors.New("executable inventory is not NUL terminated")
			}
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read executable inventory: %w", err)
		}
		path, executable, err := parseExecutableRecord(record)
		if err != nil {
			return nil, err
		}
		if executable {
			files = append(files, path)
		}
		if len(files) > maxInventoryPaths {
			return nil, errors.New("executable inventory exceeds the path limit")
		}
	}
}

func parseExecutableRecord(record []byte) (string, bool, error) {
	if len(record) == 0 || record[len(record)-1] != 0 {
		return "", false, errors.New("executable inventory is not NUL terminated")
	}
	fields := strings.SplitN(string(record[:len(record)-1]), "\t", 2)
	if len(fields) != 2 || len(fields[1]) > maxInventoryPathBytes {
		return "", false, errors.New("invalid executable inventory record")
	}
	metadata := strings.Fields(fields[0])
	if len(metadata) != 3 {
		return "", false, errors.New("invalid executable inventory metadata")
	}
	return fields[1], metadata[0] == gitExecutableMode, nil
}
