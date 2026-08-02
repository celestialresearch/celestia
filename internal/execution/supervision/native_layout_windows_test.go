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

package supervision

import (
	"golang.org/x/sys/windows"
	"os"

	"testing"

	"unsafe"
)

func TestNativeHelpersRejectInvalidState(t *testing.T) {
	t.Run("locked path", func(t *testing.T) {
		if _, err := openLocked("invalid\x00path", windows.GENERIC_READ, windows.OPEN_EXISTING); err == nil {
			t.Fatal("invalid path was accepted")
		}
	})
	t.Run("closed hash", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "closed")
		if err != nil {
			t.Fatalf("create file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close file: %v", err)
		}
		if _, err := hashFile(file); err == nil {
			t.Fatal("closed file was hashed")
		}
	})
	t.Run("closed file cleanup", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "closed")
		if err != nil {
			t.Fatalf("create file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close file: %v", err)
		}
		if err := closeFiles(file); err == nil {
			t.Fatal("failed file cleanup was reported complete")
		}
	})
	t.Run("write handle", func(t *testing.T) {
		result := newInputWriter(windows.InvalidHandle).write([]byte("frame"))
		if result.err == nil {
			t.Fatal("invalid write handle was accepted")
		}
	})
}

func TestNativeStructureLayouts(t *testing.T) {
	t.Parallel()
	var capabilities securityCapabilities
	if size := unsafe.Sizeof(capabilities); size != 24 {
		t.Fatalf("security capabilities size = %d, want 24", size)
	}
	if offset := unsafe.Offsetof(capabilities.appContainerSID); offset != 0 {
		t.Fatalf("AppContainer SID offset = %d, want 0", offset)
	}
	var accounting jobAccounting
	if size := unsafe.Sizeof(accounting); size != 48 {
		t.Fatalf("job accounting size = %d, want 48", size)
	}
	if offset := unsafe.Offsetof(accounting.activeProcesses); offset != 40 {
		t.Fatalf("active process offset = %d, want 40", offset)
	}
}
