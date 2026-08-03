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
