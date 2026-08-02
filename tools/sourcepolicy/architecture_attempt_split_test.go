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
	"strings"
	"testing"
)

func TestAttemptSplitInventory(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	findings, err := attemptSplitDeclarationFindings(files, readSource)
	if err != nil {
		t.Fatalf("inspect declarations: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %v", findings)
	}
}

func TestAttemptSplitInventoryRejectsRepositoryMutation(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	read := func(file string) ([]byte, error) {
		source, readErr := readSource(file)
		if readErr != nil {
			return nil, readErr
		}
		if file == attemptSplitDirectory+"record.go" {
			source = append(source, []byte("\nfunc injectedDeclaration(value string) error { return nil }\n")...)
		}
		return source, nil
	}
	findings, err := attemptSplitDeclarationFindings(files, read)
	if err != nil {
		t.Fatalf("inspect declarations: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "source inventory differs") {
		t.Fatalf("findings = %v, want source inventory rejection", findings)
	}
}

func TestAttemptSplitInventorySeparatesDimensions(t *testing.T) {
	t.Parallel()
	file := attemptSplitDirectory + "record_windows_test.go"
	baseline := []byte("//go:build windows\n\npackage attemptstore\nconst limit = 1\nfunc TestRecord(t *testing.T) {}\n")
	want, err := attemptSplitInventoryFor([]string{file}, fixtureReader(map[string][]byte{file: baseline}))
	if err != nil {
		t.Fatalf("baseline inventory: %v", err)
	}
	for name, source := range map[string][]byte{
		"build":     []byte("//go:build linux\n\npackage attemptstore\nconst limit = 1\nfunc TestRecord(t *testing.T) {}\n"),
		"package":   []byte("//go:build windows\n\npackage evidence\nconst limit = 1\nfunc TestRecord(t *testing.T) {}\n"),
		"signature": []byte("//go:build windows\n\npackage attemptstore\nconst limit = 1\nfunc TestRecord(t *testing.T, value string) {}\n"),
		"target":    []byte("//go:build windows\n\npackage attemptstore\nconst limit = 1\nfunc TestRenamed(t *testing.T) {}\n"),
		"import":    []byte("//go:build windows\n\npackage attemptstore\nimport _ \"example.test/sideeffect\"\nconst limit = 1\nfunc TestRecord(t *testing.T) {}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, inventoryErr := attemptSplitInventoryFor(
				[]string{file}, fixtureReader(map[string][]byte{file: source}),
			)
			if name == "package" {
				if inventoryErr == nil || !strings.Contains(inventoryErr.Error(), "uses package") {
					t.Fatalf("error = %v, want package rejection", inventoryErr)
				}
				return
			}
			if inventoryErr != nil {
				t.Fatalf("changed inventory: %v", inventoryErr)
			}
			switch name {
			case "build":
				if got.packages == want.packages {
					t.Fatal("build change was accepted")
				}
			case "signature", "import":
				if got.sources == want.sources {
					t.Fatal("signature change was accepted")
				}
			case "target":
				if got.targets == want.targets {
					t.Fatal("test target change was accepted")
				}
			}
		})
	}
}

func TestAttemptSplitInventoryBindsPath(t *testing.T) {
	t.Parallel()
	source := []byte("package attemptstore\nfunc validateRecord(value string) error { return nil }\n")
	first := attemptSplitDirectory + "record.go"
	second := attemptSplitDirectory + "validation.go"
	baseline, err := attemptSplitInventoryFor([]string{first}, fixtureReader(map[string][]byte{first: source}))
	if err != nil {
		t.Fatalf("baseline inventory: %v", err)
	}
	moved, err := attemptSplitInventoryFor([]string{second}, fixtureReader(map[string][]byte{second: source}))
	if err != nil {
		t.Fatalf("moved inventory: %v", err)
	}
	if baseline.sources == moved.sources || baseline.packages == moved.packages {
		t.Fatal("moved declaration was accepted")
	}
}

func TestAttemptSplitInventoryIgnoresFunctionBodies(t *testing.T) {
	t.Parallel()
	file := attemptSplitDirectory + "record.go"
	first := []byte("package attemptstore\nfunc validateRecord(value string) error { return nil }\n")
	second := []byte("package attemptstore\nfunc validateRecord(value string) error { panic(value) }\n")
	want, err := attemptSplitInventoryFor([]string{file}, fixtureReader(map[string][]byte{file: first}))
	if err != nil {
		t.Fatalf("baseline inventory: %v", err)
	}
	got, err := attemptSplitInventoryFor([]string{file}, fixtureReader(map[string][]byte{file: second}))
	if err != nil {
		t.Fatalf("changed body inventory: %v", err)
	}
	if got != want {
		t.Fatalf("function body changed structural inventory: got %+v want %+v", got, want)
	}
}

func TestGoTestTargetBoundary(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"TestRecord", "FuzzRecord", "BenchmarkRecord", "Test"} {
		if !isGoTestTarget(name) {
			t.Fatalf("%s was not recognised as a test target", name)
		}
	}
	for _, name := range []string{"Testimony", "Fuzzy", "Benchmarking", "helper"} {
		if isGoTestTarget(name) {
			t.Fatalf("%s was incorrectly recognised as a test target", name)
		}
	}
}

func TestAttemptSplitInventoryDetectsDuplicateDeclaration(t *testing.T) {
	t.Parallel()
	files := []string{attemptSplitDirectory + "first.go", attemptSplitDirectory + "second.go"}
	baseline := map[string][]byte{
		files[0]: []byte("package attemptstore\nfunc validateRecord() {}\n"),
		files[1]: []byte("package attemptstore\nfunc validateOther() {}\n"),
	}
	duplicate := map[string][]byte{
		files[0]: baseline[files[0]],
		files[1]: []byte("package attemptstore\nfunc validateRecord() {}\n"),
	}
	want, err := attemptSplitInventoryFor(files, fixtureReader(baseline))
	if err != nil {
		t.Fatalf("baseline inventory: %v", err)
	}
	got, err := attemptSplitInventoryFor(files, fixtureReader(duplicate))
	if err != nil {
		t.Fatalf("duplicate inventory: %v", err)
	}
	if got.sources == want.sources {
		t.Fatal("duplicate declaration was accepted")
	}
}

func TestAttemptSplitInventoryFailsClosed(t *testing.T) {
	t.Parallel()
	file := attemptSplitDirectory + "record.go"
	for name, read := range map[string]func(string) ([]byte, error){
		"missing": func(string) ([]byte, error) { return nil, errors.New("missing") },
		"malformed source": func(string) ([]byte, error) {
			return []byte("package attemptstore\nfunc"), nil
		},
		"malformed build": func(string) ([]byte, error) {
			return []byte("//go:build (windows\n\npackage attemptstore\n"), nil
		},
		"multiple build": func(string) ([]byte, error) {
			return []byte("//go:build windows\n//go:build amd64\n\npackage attemptstore\n"), nil
		},
		"legacy build": func(string) ([]byte, error) {
			return []byte("// +build windows\n\npackage attemptstore\n"), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := attemptSplitInventoryFor([]string{file}, read)
			if err == nil || !strings.Contains(err.Error(), "attempt split") {
				t.Fatalf("error = %v, want attempt split failure", err)
			}
		})
	}
}

func fixtureReader(files map[string][]byte) func(string) ([]byte, error) {
	return func(file string) ([]byte, error) {
		source, ok := files[file]
		if !ok {
			return nil, errors.New("missing fixture")
		}
		return source, nil
	}
}
