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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	modeGoTestInventory    = "go-test-inventory"
	modeCargoTestInventory = "cargo-test-inventory"

	maxTestInventoryBytes   = 16 << 20
	maxCargoMessageBytes    = 1 << 20
	maxCargoTestExecutables = 10_000
	testInventoryTimeout    = 2 * time.Minute
)

type goPackageInventory struct {
	Dir          string   `json:"Dir"`
	ImportPath   string   `json:"ImportPath"`
	TestGoFiles  []string `json:"TestGoFiles"`
	XTestGoFiles []string `json:"XTestGoFiles"`
}

type cargoMessage struct {
	Reason       string `json:"reason"`
	Executable   string `json:"executable"`
	ManifestPath string `json:"manifest_path"`
	Profile      struct {
		Test bool `json:"test"`
	} `json:"profile"`
}

type cargoExecutable struct {
	directory  string
	executable string
}

func runTestInventory(
	args []string,
	input io.Reader,
	output, stderr io.Writer,
) (bool, int) {
	if len(args) != 1 ||
		(args[0] != modeGoTestInventory &&
			args[0] != modeCargoTestInventory) {
		return false, 0
	}
	var err error
	if args[0] == modeGoTestInventory {
		err = writeGoInventory(output)
	} else {
		err = writeCargoExecutables(input, output)
	}
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return true, 1
		}
		return true, 1
	}
	return true, 0
}

func writeGoInventory(output io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), testInventoryTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "list", "-json", "./...")
	command.Stderr = os.Stderr
	var data boundedInventoryBuffer
	command.Stdout = &data
	runErr := command.Run()
	if data.err != nil {
		return data.err
	}
	if runErr != nil {
		return fmt.Errorf("list Go packages: %w", runErr)
	}
	decoder := json.NewDecoder(bytes.NewReader(data.Bytes()))
	var inventory []string
	for decoder.More() {
		var pkg goPackageInventory
		if err := decoder.Decode(&pkg); err != nil {
			return fmt.Errorf("decode Go package: %w", err)
		}
		for _, name := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
			tests, err := testsInFile(filepath.Join(pkg.Dir, name))
			if err != nil {
				return err
			}
			for _, test := range tests {
				inventory = append(inventory, pkg.ImportPath+"\t"+test)
			}
		}
	}
	sort.Strings(inventory)
	for _, entry := range inventory {
		if _, err := fmt.Fprintln(output, entry); err != nil {
			return err
		}
	}
	return nil
}

func testsInFile(path string) ([]string, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var tests []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || function.Name == nil {
			continue
		}
		if validGoTestName(function.Name.Name) {
			tests = append(tests, function.Name.Name)
		}
	}
	for _, example := range doc.Examples(file) {
		if example.Output != "" || example.EmptyOutput {
			tests = append(tests, "Example"+example.Name)
		}
	}
	return tests, nil
}

func validGoTestName(name string) bool {
	if name == "TestMain" {
		return false
	}
	for _, prefix := range []string{"Test", "Fuzz"} {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			next, _ := utf8.DecodeRuneInString(name[len(prefix):])
			return !unicode.IsLower(next)
		}
	}
	return false
}

func writeCargoExecutables(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxCargoMessageBytes)
	seen := make(map[cargoExecutable]struct{})
	var executables []cargoExecutable
	for scanner.Scan() {
		var message cargoMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			return fmt.Errorf("decode Cargo message: %w", err)
		}
		entry, include, err := cargoExecutableFromMessage(message)
		if err != nil {
			return err
		}
		if !include {
			continue
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		executables = append(executables, entry)
		if len(executables) > maxCargoTestExecutables {
			return fmt.Errorf(
				"cargo test executable inventory exceeds %d entries",
				maxCargoTestExecutables,
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	sort.Slice(executables, func(left, right int) bool {
		if executables[left].directory == executables[right].directory {
			return executables[left].executable < executables[right].executable
		}
		return executables[left].directory < executables[right].directory
	})
	for _, executable := range executables {
		if _, err := fmt.Fprintf(
			output,
			"%s\t%s\n",
			executable.directory,
			executable.executable,
		); err != nil {
			return err
		}
	}
	return nil
}

func cargoExecutableFromMessage(
	message cargoMessage,
) (cargoExecutable, bool, error) {
	if message.Reason != "compiler-artifact" ||
		!message.Profile.Test ||
		message.Executable == "" {
		return cargoExecutable{}, false, nil
	}
	if message.ManifestPath == "" {
		return cargoExecutable{}, false, fmt.Errorf(
			"cargo test inventory omits the package manifest",
		)
	}
	if !validCargoPath(message.ManifestPath) ||
		!validCargoPath(message.Executable) {
		return cargoExecutable{}, false, fmt.Errorf(
			"cargo test inventory contains an invalid path",
		)
	}
	return cargoExecutable{
		directory:  filepath.Dir(message.ManifestPath),
		executable: message.Executable,
	}, true, nil
}

func validCargoPath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\t\r\n")
}

type boundedInventoryBuffer struct {
	data bytes.Buffer
	err  error
}

func (buffer *boundedInventoryBuffer) Bytes() []byte {
	return buffer.data.Bytes()
}

func (buffer *boundedInventoryBuffer) Len() int {
	return buffer.data.Len()
}

func (buffer *boundedInventoryBuffer) Write(data []byte) (int, error) {
	if buffer.err != nil {
		return 0, buffer.err
	}
	if buffer.Len()+len(data) > maxTestInventoryBytes {
		buffer.err = fmt.Errorf(
			"go test inventory exceeds %d bytes",
			maxTestInventoryBytes,
		)
		return 0, buffer.err
	}
	return buffer.data.Write(data)
}
