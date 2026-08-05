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
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestSupervisionSplitInventory(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	findings, err := supervisionSplitDeclarationFindings(files, readSource)
	if err != nil {
		t.Fatalf("inspect supervision declarations: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %v", findings)
	}
}

func TestArchitecturePolicyRejectsSupervisionSplitDrift(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	const (
		first  = supervisionSplitDirectory + "cleanup_windows.go"
		second = supervisionSplitDirectory + "wait_windows.go"
	)
	firstSource, err := readSource(first)
	if err != nil {
		t.Fatal(err)
	}
	secondSource, err := readSource(second)
	if err != nil {
		t.Fatal(err)
	}
	for name, fixture := range supervisionSplitDriftFixtures(files, firstSource, secondSource) {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			inventory := func() ([]string, error) { return fixture.inventory, nil }
			if status := runArchitecturePolicy(
				&stderr, inventory, sourceExecutables, fixture.read,
			); status == 0 || !strings.Contains(stderr.String(), "supervision") {
				t.Fatalf("status = %d, stderr = %q", status, stderr.String())
			}
		})
	}
}

type supervisionSplitDrift struct {
	inventory []string
	read      func(string) ([]byte, error)
}

func supervisionSplitDriftFixtures(
	files []string,
	firstSource []byte,
	secondSource []byte,
) map[string]supervisionSplitDrift {
	const (
		first  = supervisionSplitDirectory + "cleanup_windows.go"
		second = supervisionSplitDirectory + "wait_windows.go"
	)
	return map[string]supervisionSplitDrift{
		"missing file": {
			inventory: slices.DeleteFunc(slices.Clone(files), func(file string) bool { return file == first }),
			read:      readSource,
		},
		"extra file": {
			inventory: append(slices.Clone(files), supervisionSplitDirectory+"undeclared.s"),
			read:      readSource,
		},
		"moved owner": {
			inventory: files,
			read: func(file string) ([]byte, error) {
				switch file {
				case first:
					return secondSource, nil
				case second:
					return firstSource, nil
				default:
					return readSource(file)
				}
			},
		},
		"changed constraint": {
			inventory: files,
			read: func(file string) ([]byte, error) {
				source, readErr := readSource(file)
				if readErr == nil && file == first {
					source = append([]byte("//go:build windows\n\n"), source...)
				}
				return source, readErr
			},
		},
	}
}

func TestSupervisionSplitInventoryBindsOwner(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	want, err := supervisionSplitInventoryFor(files, readSource, supervisionSplitOwners)
	if err != nil {
		t.Fatalf("baseline inventory: %v", err)
	}
	owners := map[string]string{}
	maps.Copy(owners, supervisionSplitOwners)
	owners["cleanup_windows.go"] = "wait"
	got, err := supervisionSplitInventoryFor(files, readSource, owners)
	if err != nil {
		t.Fatalf("mutated inventory: %v", err)
	}
	if got.packages == want.packages {
		t.Fatal("owner mutation survived")
	}
}

func TestSupervisionSplitBindsSuspendedStart(t *testing.T) {
	t.Chdir("../..")
	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	mutated := func(path string) ([]byte, error) {
		source, readErr := readSource(path)
		if readErr != nil || path != supervisionStartFile {
			return source, readErr
		}
		before := []byte("extendedStartupInfoPresent|createSuspended|createNoWindow")
		after := []byte("extendedStartupInfoPresent|createNoWindow")
		changed := bytes.Replace(source, before, after, 1)
		if bytes.Equal(changed, source) {
			t.Fatal("suspended creation mutation did not change source")
		}
		return changed, nil
	}
	findings, err := supervisionSplitDeclarationFindings(files, mutated)
	if err != nil {
		t.Fatalf("inspect mutated supervision declaration: %v", err)
	}
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, "suspended start body differs")
	}) {
		t.Fatalf("findings = %v, want suspended start body rejection", findings)
	}
}

func TestSupervisionSplitRequiresStartBody(t *testing.T) {
	t.Chdir("../..")
	readFile := func(path string) ([]byte, error) {
		source, err := readSource(path)
		if err == nil && path == supervisionStartFile {
			source = bytes.Replace(
				source, []byte("func startSuspendedWith("), []byte("func removedStart("), 1,
			)
		}
		return source, err
	}
	_, err := supervisionStartBodyInventory(readFile)
	if err == nil || !strings.Contains(err.Error(), "declaration is missing") {
		t.Fatalf("missing declaration error = %v", err)
	}
}

func TestSupervisionSplitRejectsDuplicateStart(t *testing.T) {
	t.Chdir("../..")

	_, err := supervisionStartBodyInventory(func(path string) ([]byte, error) {
		source, readErr := readSource(path)
		if readErr != nil || path != supervisionStartFile {
			return source, readErr
		}
		return append(source, []byte("\nfunc startSuspendedWith() {}\n")...), nil
	})
	if err == nil || !strings.Contains(err.Error(), "declaration is invalid") {
		t.Fatalf("duplicate declaration error = %v", err)
	}
}

func TestSupervisionSplitRejectsUnknownFile(t *testing.T) {
	t.Chdir("../..")
	const unknown = supervisionSplitDirectory + "unknown.go"
	files := supervisionInventoryFiles(t)
	files = replaceSupervisionFile(
		t, files, supervisionSplitDirectory+"cleanup_windows.go", unknown,
	)
	readFile := func(path string) ([]byte, error) {
		if path == unknown {
			return nil, errors.New("unexpected source read")
		}
		return readSource(path)
	}

	inventory, err := supervisionSplitInventoryFor(files, readFile, supervisionSplitOwners)
	if err != nil {
		t.Fatalf("inventory unknown file: %v", err)
	}
	want := hashInventory([]string{inventoryRecord("unexpected-file", unknown)})
	if inventory.packages != want {
		t.Fatalf("unknown file inventory = %q, want %q", inventory.packages, want)
	}
}

func TestSupervisionSplitRejectsNonGoFile(t *testing.T) {
	t.Chdir("../..")
	const nonGo = supervisionSplitDirectory + "cleanup_windows.rs"
	files := supervisionInventoryFiles(t)
	files = replaceSupervisionFile(
		t, files, supervisionSplitDirectory+"cleanup_windows.go", nonGo,
	)
	owners := maps.Clone(supervisionSplitOwners)
	owner := owners["cleanup_windows.go"]
	delete(owners, "cleanup_windows.go")
	owners["cleanup_windows.rs"] = owner
	readFile := func(path string) ([]byte, error) {
		if path == nonGo {
			return nil, errors.New("unexpected source read")
		}
		return readSource(path)
	}

	inventory, err := supervisionSplitInventoryFor(files, readFile, owners)
	if err != nil {
		t.Fatalf("inventory non-Go file: %v", err)
	}
	want := hashInventory([]string{inventoryRecord("unexpected-file", nonGo)})
	if inventory.packages != want {
		t.Fatalf("non-Go file inventory = %q, want %q", inventory.packages, want)
	}
}

func TestSupervisionSplitBoundsAggregateSource(t *testing.T) {
	t.Chdir("../..")
	files := supervisionInventoryFiles(t)
	readFile := func(path string) ([]byte, error) {
		source, err := readSource(path)
		if err != nil || path != supervisionStartFile {
			return source, err
		}
		return append(source, bytes.Repeat([]byte(" "), maxSupervisionSplitBytes-len(source)+1)...), nil
	}

	_, err := supervisionSplitInventoryFor(files, readFile, supervisionSplitOwners)
	if err == nil || !strings.Contains(err.Error(), "source inventory exceeds bound") {
		t.Fatalf("aggregate bound error = %v", err)
	}
}

func TestSupervisionSplitRejectsWrongPackage(t *testing.T) {
	t.Chdir("../..")
	files := supervisionInventoryFiles(t)
	readFile := func(path string) ([]byte, error) {
		source, err := readSource(path)
		if err != nil || path != supervisionStartFile {
			return source, err
		}
		return bytes.Replace(source, []byte("package supervision"), []byte("package rogue"), 1), nil
	}

	_, err := supervisionSplitInventoryFor(files, readFile, supervisionSplitOwners)
	if err == nil || !strings.Contains(err.Error(), "uses package rogue") {
		t.Fatalf("wrong package error = %v", err)
	}
}

func supervisionInventoryFiles(t *testing.T) []string {
	t.Helper()

	files, err := sourceFiles()
	if err != nil {
		t.Fatalf("inventory source: %v", err)
	}
	return files
}

func replaceSupervisionFile(t *testing.T, files []string, declared, replacement string) []string {
	t.Helper()

	replaced := false
	updated := slices.Clone(files)
	for index, path := range updated {
		if path == declared {
			updated[index] = replacement
			replaced = true
		}
	}
	if !replaced {
		t.Fatalf("missing declared file %q", declared)
	}
	return updated
}
