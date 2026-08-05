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
		if err := closeFilesWith((*os.File).Close, file); err == nil {
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
	var resources jobBasicAndIOAccounting
	if size := unsafe.Sizeof(resources); size != 96 {
		t.Fatalf("job resource size = %d, want 96", size)
	}
	if offset := unsafe.Offsetof(resources.io); offset != 48 {
		t.Fatalf("job I/O offset = %d, want 48", offset)
	}
	var counters processMemoryCounters
	if size := unsafe.Sizeof(counters); size != 72 {
		t.Fatalf("process counters size = %d, want 72", size)
	}
	if offset := unsafe.Offsetof(counters.peakWorkingSet); offset != 8 {
		t.Fatalf("peak working set offset = %d, want 8", offset)
	}
}
