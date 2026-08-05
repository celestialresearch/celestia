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
	"io"
	"slices"
	"strings"
	"testing"
)

func TestSourceFiles(t *testing.T) {
	t.Parallel()
	files, err := readInventory(strings.NewReader("first.go\x00second.rs\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, []string{"first.go", "second.rs"}) {
		t.Fatalf("files = %v", files)
	}
	tests := []struct {
		name   string
		source io.Reader
	}{
		{"unterminated", strings.NewReader("first.go")},
		{"empty", strings.NewReader("\x00")},
		{
			"long path",
			strings.NewReader("aaaaaaaaa\x00"),
		},
		{
			"too many paths",
			strings.NewReader("a\x00b\x00"),
		},
		{
			"too many bytes",
			strings.NewReader("aa\x00bb\x00"),
		},
		{"read failure", failingReader{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			maxBytes, maxPaths, maxPathBytes := 64, 8, 8
			switch test.name {
			case "too many paths":
				maxPaths = 1
			case "too many bytes":
				maxBytes = 5
			}
			if _, err := readInventoryWithLimits(
				test.source, maxBytes, maxPaths, maxPathBytes,
			); err == nil {
				t.Fatal("readInventory accepted invalid input")
			}
		})
	}
}

func TestSourceFilesCommand(t *testing.T) {
	t.Parallel()
	files, err := inventorySourceFiles(
		&fakeInventoryCommand{output: strings.NewReader("main.go\x00")},
		func() {},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(files, "main.go") {
		t.Fatalf("source inventory does not contain sourcepolicy: %v", files)
	}
	tests := []struct {
		name    string
		command *fakeInventoryCommand
	}{
		{"pipe failure", &fakeInventoryCommand{pipeErr: errors.New("pipe failed")}},
		{"start failure", &fakeInventoryCommand{startErr: errors.New("start failed")}},
		{
			"read failure",
			&fakeInventoryCommand{output: failingReader{}},
		},
		{
			"wait failure",
			&fakeInventoryCommand{
				output:  strings.NewReader("main.go\x00"),
				waitErr: errors.New("wait failed"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := inventorySourceFiles(test.command, func() {})
			if err == nil {
				t.Fatal("inventorySourceFiles accepted a command failure")
			}
		})
	}
}

func TestSourceFilesRejectsEmptyInventory(t *testing.T) {
	t.Parallel()

	_, err := inventorySourceFiles(
		&fakeInventoryCommand{output: strings.NewReader("")},
		func() {},
	)
	if err == nil || !strings.Contains(err.Error(), "source inventory is empty") {
		t.Fatalf("empty inventory error = %v", err)
	}
}

type fakeInventoryCommand struct {
	output   io.Reader
	pipeErr  error
	startErr error
	waitErr  error
}

func (command *fakeInventoryCommand) Start() error {
	return command.startErr
}

func (command *fakeInventoryCommand) StdoutPipe() (io.ReadCloser, error) {
	if command.pipeErr != nil {
		return nil, command.pipeErr
	}
	return io.NopCloser(command.output), nil
}

func (command *fakeInventoryCommand) Wait() error {
	return command.waitErr
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}
