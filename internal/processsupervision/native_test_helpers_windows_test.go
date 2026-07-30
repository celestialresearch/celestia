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

//go:build windows && amd64

package processsupervision

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testNativeLimits() Limits {
	return Limits{
		InputBytes:     65_536,
		OutputBytes:    8192,
		ErrorBytes:     8192,
		MemoryBytes:    67_108_864,
		Processes:      1,
		StartupTimeout: 10 * time.Second,
		Timeout:        500 * time.Millisecond,
		CleanupTimeout: time.Second,
	}
}

func copyFile(t *testing.T, target, source string) {
	t.Helper()
	sourceRoot, err := os.OpenRoot(filepath.Dir(source))
	if err != nil {
		t.Fatalf("open fixture root: %v", err)
	}
	t.Cleanup(func() {
		if err := sourceRoot.Close(); err != nil {
			t.Errorf("close fixture root: %v", err)
		}
	})
	data, err := sourceRoot.ReadFile(filepath.Base(source))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	targetRoot, err := os.OpenRoot(filepath.Dir(target))
	if err != nil {
		t.Fatalf("open destination root: %v", err)
	}
	t.Cleanup(func() {
		if err := targetRoot.Close(); err != nil {
			t.Errorf("close destination root: %v", err)
		}
	})
	if err := targetRoot.WriteFile(filepath.Base(target), data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func closeContainer(t *testing.T, container *appContainer) {
	t.Helper()
	if err := container.close(); err != nil {
		t.Errorf("close container: %v", err)
	}
}

func closeFile(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil {
		t.Errorf("close file: %v", err)
	}
}

func nativePipe(t *testing.T) (windows.Handle, windows.Handle) {
	t.Helper()
	var read windows.Handle
	var write windows.Handle
	if err := windows.CreatePipe(&read, &write, nil, 0); err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	return read, write
}

func closeNativeHandle(t *testing.T, handle windows.Handle) {
	t.Helper()
	if err := windows.CloseHandle(handle); err != nil {
		t.Errorf("close handle: %v", err)
	}
}
