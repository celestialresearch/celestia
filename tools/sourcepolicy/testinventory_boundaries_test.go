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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type rejectedWrite struct{}

func (rejectedWrite) Write([]byte) (int, error) {
	return 0, errors.New("write rejected")
}

func TestRunTestInventoryReportsFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var stderr bytes.Buffer
	handled, status := runTestInventory(
		[]string{modeGoTestInventory},
		bytes.NewReader(nil),
		&stderr,
		&stderr,
	)
	if !handled || status != 1 {
		t.Fatalf("runTestInventory() = %t, %d", handled, status)
	}
	if !strings.Contains(stderr.String(), "list Go packages") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	handled, status = runTestInventory(
		[]string{modeCargoTestInventory},
		strings.NewReader("invalid\n"),
		&stderr,
		rejectedWrite{},
	)
	if !handled || status != 1 {
		t.Fatalf("runTestInventory() = %t, %d", handled, status)
	}
}

func TestWriteGoInventory(t *testing.T) {
	setFixture := newInventoryFixture(t)
	t.Run("discovers tests", func(t *testing.T) {
		root := writeInventoryTestFile(t)
		setFixture(t, fmt.Sprintf(
			`{"Dir":%q,"ImportPath":"example.test/sample",`+
				`"TestGoFiles":["sample_test.go"]}`,
			root,
		))
		var output bytes.Buffer
		if err := writeGoInventory(&output); err != nil {
			t.Fatal(err)
		}
		if got, want := output.String(), "example.test/sample\tTestOutput\n"; got != want {
			t.Fatalf("output = %q, want %q", got, want)
		}
	})
	tests := []struct {
		name   string
		output string
		err    string
	}{
		{"oversized output", strings.Repeat("x", maxTestInventoryBytes+(64<<10)), "exceeds"},
		{"malformed package", "{", "decode Go package"},
		{
			"missing test file",
			fmt.Sprintf(
				`{"Dir":%q,"ImportPath":"example.test/missing",`+
					`"TestGoFiles":["missing_test.go"]}`,
				t.TempDir(),
			),
			"parse ",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setFixture(t, test.output)
			if err := writeGoInventory(&bytes.Buffer{}); err == nil ||
				!strings.Contains(err.Error(), test.err) {
				t.Fatalf("writeGoInventory() error = %v, want %q", err, test.err)
			}
		})
	}
	t.Run("rejects output failure", func(t *testing.T) {
		setFixture(t, fmt.Sprintf(
			`{"Dir":%q,"ImportPath":"example.test/sample",`+
				`"TestGoFiles":["sample_test.go"]}`,
			writeInventoryTestFile(t),
		))
		if err := writeGoInventory(rejectedWrite{}); err == nil ||
			!strings.Contains(err.Error(), "write rejected") {
			t.Fatalf("writeGoInventory() error = %v", err)
		}
	})
}

func TestTestsInFileRejectsInvalidSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken_test.go")
	if err := os.WriteFile(path, []byte("package broken\nfunc {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := testsInFile(path); err == nil ||
		!strings.Contains(err.Error(), "parse ") {
		t.Fatalf("testsInFile() error = %v", err)
	}
}

func TestGoTestNamesRejectInvalidForms(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "Test", "Fuzz", "TestMain", "Testlower", "BenchmarkOnly"} {
		if validGoTestName(name) {
			t.Errorf("validGoTestName(%q) = true", name)
		}
	}
	for _, name := range []string{"TestUpper", "Test_underscore", "Fuzz1"} {
		if !validGoTestName(name) {
			t.Errorf("validGoTestName(%q) = false", name)
		}
	}
}

func TestWriteCargoExecutablesEnforcesBounds(t *testing.T) {
	t.Parallel()
	oversized := strings.Repeat("x", maxCargoMessageBytes+1)
	if err := writeCargoExecutables(
		strings.NewReader(oversized),
		&bytes.Buffer{},
	); err == nil {
		t.Fatal("oversized Cargo message was accepted")
	}

	var input strings.Builder
	root := t.TempDir()
	manifest := filepath.Join(root, "Cargo.toml")
	for index := range maxCargoTestExecutables + 1 {
		fmt.Fprintf(
			&input,
			"{\"reason\":\"compiler-artifact\",\"profile\":{\"test\":true},"+
				"\"manifest_path\":%q,\"executable\":%q}\n",
			manifest,
			filepath.Join(root, fmt.Sprintf("test-%d", index)),
		)
	}
	if err := writeCargoExecutables(
		strings.NewReader(input.String()),
		&bytes.Buffer{},
	); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("executable limit error = %v", err)
	}
}

func TestWriteCargoExecutablesRejectsOutputFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	input := strings.NewReader(fmt.Sprintf(
		"{\"reason\":\"compiler-artifact\",\"profile\":{\"test\":true},"+
			"\"manifest_path\":%q,\"executable\":%q}\n",
		filepath.Join(root, "Cargo.toml"),
		filepath.Join(root, "test"),
	))
	if err := writeCargoExecutables(input, rejectedWrite{}); err == nil ||
		!strings.Contains(err.Error(), "write rejected") {
		t.Fatalf("writeCargoExecutables() error = %v", err)
	}
}

func TestBoundedInventoryBuffer(t *testing.T) {
	t.Parallel()
	var buffer boundedInventoryBuffer
	if _, bypassesWrite := any(&buffer).(io.ReaderFrom); bypassesWrite {
		t.Fatal("inventory buffer exposes a ReadFrom path around Write")
	}
	if count, err := buffer.Write([]byte("valid")); err != nil || count != 5 {
		t.Fatalf("Write() = %d, %v", count, err)
	}
	if _, err := buffer.Write(make([]byte, maxTestInventoryBytes)); err == nil {
		t.Fatal("oversized inventory was accepted")
	}
	if _, err := buffer.Write([]byte("later")); err == nil {
		t.Fatal("write after overflow was accepted")
	}
}

func newInventoryFixture(t *testing.T) func(*testing.T, string) {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "main.go")
	program := `package main
import ("io"; "os")
func main() {
	file, err := os.Open(os.Getenv("CELESTIA_INVENTORY_FIXTURE"))
	if err != nil { os.Exit(1) }
	defer file.Close()
	if _, err = io.Copy(os.Stdout, file); err != nil { os.Exit(1) }
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	command := exec.CommandContext(t.Context(), "go", "build", "-o", name, "main.go")
	command.Dir = directory
	if buildOutput, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build inventory fixture: %v\n%s", err, buildOutput)
	}
	return func(t *testing.T, output string) {
		t.Helper()
		fixture := filepath.Join(t.TempDir(), "fixture")
		if err := os.WriteFile(fixture, []byte(output), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory)
		t.Setenv("CELESTIA_INVENTORY_FIXTURE", fixture)
	}
}

func writeInventoryTestFile(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source := "package sample\nimport \"testing\"\nfunc TestOutput(*testing.T) {}\n"
	if err := os.WriteFile(
		filepath.Join(root, "sample_test.go"),
		[]byte(source),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return root
}
