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

//go:build linux && amd64

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
)

func TestBootstrapMainFailsClosed(t *testing.T) {
	if os.Getenv("CELESTIA_BOOTSTRAP_MAIN_HELPER") == "1" {
		if status := runBootstrapMain(); status != 1 {
			t.Fatalf("bootstrap status = %d", status)
		}
		return
	}
	testBootstrapMainFailsClosed(t)
}

func testBootstrapMainFailsClosed(t *testing.T) {
	readyRead, readyWrite := testPipe(t)
	gateRead, gateWrite := testPipe(t)
	fixture, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	cleanupBootstrapFiles(t, readyRead, readyWrite, gateRead, gateWrite, fixture)
	runBootstrapHelper(t, readyWrite, gateRead, gateWrite, fixture)
	assertBootstrapNotReady(t, readyRead)
}

func cleanupBootstrapFiles(t *testing.T, files ...*os.File) {
	t.Helper()
	for _, file := range files {
		t.Cleanup(func() {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Errorf("close bootstrap file: %v", err)
			}
		})
	}
}

func runBootstrapHelper(t *testing.T, readyWrite, gateRead, gateWrite, fixture *os.File) {
	t.Helper()
	if _, err := gateWrite.Write([]byte{'g'}); err != nil {
		t.Fatal(err)
	}
	if err := gateWrite.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestBootstrapMainFailsClosed$")
	command.Env = append(os.Environ(), "CELESTIA_BOOTSTRAP_MAIN_HELPER=1")
	command.ExtraFiles = []*os.File{readyWrite, gateRead, fixture}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{readyWrite, gateRead, fixture} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("bootstrap helper error = %v", err)
	}
}

func assertBootstrapNotReady(t *testing.T, readyRead *os.File) {
	t.Helper()
	data := make([]byte, 1)
	if count, err := readyRead.Read(data); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("bootstrap readiness count=%d error=%v", count, err)
	}
	if err := readyRead.Close(); err != nil {
		t.Fatal(err)
	}
}

func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	return read, write
}
