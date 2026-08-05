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
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStageImageRejectsInvalidBoundaries(t *testing.T) {
	source := filepath.Join(t.TempDir(), "worker.exe")
	if err := os.WriteFile(source, []byte("worker"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if _, _, _, _, err := stageImage("invalid\x00folder", source); err == nil {
		t.Fatal("invalid staging folder accepted")
	}
	if _, _, _, _, err := stageImage(
		t.TempDir(),
		filepath.Join(t.TempDir(), "missing.exe"),
	); err == nil {
		t.Fatal("missing worker accepted")
	}
	folder := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(folder, "worker.exe"),
		[]byte("occupied"),
		0o600,
	); err != nil {
		t.Fatalf("write occupied target: %v", err)
	}
	if _, _, _, _, err := stageImage(folder, source); err == nil {
		t.Fatal("occupied staging target replaced")
	}
}

func TestStageImageReportsOperationFailures(t *testing.T) {
	for _, test := range imageStageFailureCases() {
		t.Run(test.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "worker.exe")
			if err := os.WriteFile(source, []byte("worker"), 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}
			operations := defaultImageStageOperations()
			test.change(&operations, source)
			image, _, _, cleanupComplete, err := stageImageWith(
				t.TempDir(),
				source,
				operations,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("stage error = %v, want %q", err, test.want)
			}
			if image != nil {
				t.Fatal("failed staging retained an image")
			}
			if cleanupComplete != test.cleanupComplete {
				t.Fatalf(
					"cleanup complete = %t, want %t",
					cleanupComplete,
					test.cleanupComplete,
				)
			}
		})
	}
}

type imageStageFailureCase struct {
	name            string
	want            string
	cleanupComplete bool
	change          func(*imageStageOperations, string)
}

func imageStageFailureCases() []imageStageFailureCase {
	return []imageStageFailureCase{
		{
			name:            "copy",
			want:            "stage worker",
			cleanupComplete: true,
			change: func(operations *imageStageOperations, _ string) {
				operations.copy = func(io.Writer, io.Reader) (int64, error) {
					return 0, errors.New("copy")
				}
			},
		},
		{
			name:            "sync",
			want:            "flush staged worker",
			cleanupComplete: true,
			change: func(operations *imageStageOperations, _ string) {
				operations.sync = func(*os.File) error {
					return errors.New("sync")
				}
			},
		},
		{
			name:            "close staged",
			want:            "close staged worker",
			cleanupComplete: false,
			change: func(operations *imageStageOperations, source string) {
				closeFile := operations.close
				operations.close = func(file *os.File) error {
					if filepath.Clean(file.Name()) != filepath.Clean(source) {
						return errors.Join(closeFile(file), errors.New("close staged"))
					}
					return closeFile(file)
				}
			},
		},
		{
			name:            "reopen",
			want:            "lock staged worker",
			cleanupComplete: true,
			change: func(operations *imageStageOperations, _ string) {
				openStage := operations.openStage
				operations.openStage = func(
					path string,
					access, disposition uint32,
				) (*os.File, error) {
					if disposition == windows.OPEN_EXISTING {
						file, err := openStage(path, access, disposition)
						return file, errors.Join(err, errors.New("reopen"))
					}
					return openStage(path, access, disposition)
				}
			},
		},
		{
			name:            "verify",
			want:            "verify",
			cleanupComplete: true,
			change: func(operations *imageStageOperations, _ string) {
				operations.verify = func(*os.File, [32]byte) error {
					return errors.New("verify")
				}
			},
		},
		{
			name:            "close source",
			want:            "close worker source",
			cleanupComplete: false,
			change: func(operations *imageStageOperations, source string) {
				closeFile := operations.close
				operations.close = func(file *os.File) error {
					if filepath.Clean(file.Name()) == filepath.Clean(source) {
						return errors.Join(closeFile(file), errors.New("close source"))
					}
					return closeFile(file)
				}
			},
		},
	}
}

func TestVerifyImageStates(t *testing.T) {
	expected := sha256.Sum256([]byte("worker"))
	if err := verifyImageWith(expected, func() ([32]byte, error) {
		return expected, nil
	}); err != nil {
		t.Fatalf("matching image: %v", err)
	}
	if err := verifyImageWith(expected, func() ([32]byte, error) {
		return [32]byte{}, errors.New("hash")
	}); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("hash failure: %v", err)
	}
	if err := verifyImageWith(expected, func() ([32]byte, error) {
		return [32]byte{}, nil
	}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("image mismatch: %v", err)
	}
}

func TestHashFileRejectsClosedImage(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "closed-image-")
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
	if _, err := hashFile(file); err == nil {
		t.Fatal("closed image hashed")
	}
}

func TestHashFileReportsReadFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "hash-image-")
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close image: %v", err)
		}
	}()
	readErr := errors.New("read")
	if _, err := hashFileWith(
		file,
		(*os.File).Seek,
		func(io.Writer, io.Reader) (int64, error) {
			return 0, readErr
		},
	); !errors.Is(err, readErr) {
		t.Fatalf("hash read error = %v", err)
	}
}

func TestOpenLockedRejectsInvalidPath(t *testing.T) {
	if _, err := openLocked(
		"invalid\x00path",
		windows.GENERIC_READ,
		windows.OPEN_EXISTING,
	); err == nil {
		t.Fatal("invalid native path opened")
	}
	if _, err := openLocked(
		filepath.Join(t.TempDir(), "missing.exe"),
		windows.GENERIC_READ,
		windows.OPEN_EXISTING,
	); err == nil {
		t.Fatal("missing native path opened")
	}
}

func TestOpenLockedReportsNativeFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*lockedFileOperations)
	}{
		{
			name: "information",
			change: func(operations *lockedFileOperations) {
				operations.information = func(
					windows.Handle,
					*windows.ByHandleFileInformation,
				) error {
					return errors.New("information")
				}
			},
		},
		{
			name: "directory",
			change: func(operations *lockedFileOperations) {
				operations.information = func(
					_ windows.Handle,
					information *windows.ByHandleFileInformation,
				) error {
					information.FileAttributes = windows.FILE_ATTRIBUTE_DIRECTORY
					return nil
				}
			},
		},
		{name: "file wrapper", change: func(*lockedFileOperations) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closed := 0
			encoded := uint16('C')
			operations := lockedFileOperations{
				encode: func(string) (*uint16, error) {
					return &encoded, nil
				},
				create: func(
					*uint16,
					uint32,
					uint32,
					*windows.SecurityAttributes,
					uint32,
					uint32,
					windows.Handle,
				) (windows.Handle, error) {
					return 1, nil
				},
				information: func(
					windows.Handle,
					*windows.ByHandleFileInformation,
				) error {
					return nil
				},
				newFile: func(uintptr, string) *os.File {
					return nil
				},
				close: func(windows.Handle) error {
					closed++
					return nil
				},
			}
			test.change(&operations)
			if _, err := openLockedWith(
				`C:\worker.exe`,
				windows.GENERIC_READ,
				windows.OPEN_EXISTING,
				operations,
			); err == nil {
				t.Fatal("native failure accepted")
			}
			if closed != 1 {
				t.Fatalf("closed handles = %d, want 1", closed)
			}
		})
	}
}

func TestOpenLocalImageClosesValidationFailure(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "worker.exe")
	if err := os.WriteFile(path, []byte("worker"), 0o600); err != nil {
		t.Fatalf("write worker: %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open worker root: %v", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close worker root: %v", err)
		}
	}()
	validateErr := errors.New("validate")
	_, err = openLocalImageWith(
		path,
		func(string, uint32, uint32) (*os.File, error) {
			return root.Open("worker.exe")
		},
		func(*os.File, string) error {
			return validateErr
		},
	)
	if !errors.Is(err, validateErr) {
		t.Fatalf("validation error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("validation failure retained image handle: %v", err)
	}
}

func TestWorkerDriveTypeStates(t *testing.T) {
	if _, err := workerDriveTypeWith("worker.exe", func(*uint16) uint32 {
		return windows.DRIVE_FIXED
	}); err == nil {
		t.Fatal("relative worker volume accepted")
	}
	if _, err := workerDriveTypeWith("\x00:\\worker.exe", func(*uint16) uint32 {
		return windows.DRIVE_FIXED
	}); err == nil {
		t.Fatal("invalid worker volume accepted")
	}
	for _, unavailable := range []uint32{windows.DRIVE_UNKNOWN, windows.DRIVE_NO_ROOT_DIR} {
		if _, err := workerDriveTypeWith(`C:\worker.exe`, func(*uint16) uint32 {
			return unavailable
		}); err == nil {
			t.Fatalf("unavailable drive type %d accepted", unavailable)
		}
	}
	if kind, err := workerDriveTypeWith(`C:\worker.exe`, func(*uint16) uint32 {
		return windows.DRIVE_FIXED
	}); err != nil || kind != windows.DRIVE_FIXED {
		t.Fatalf("drive type=%d error=%v", kind, err)
	}
}

func TestFinalImagePathStates(t *testing.T) {
	resolveError := errors.New("resolve")
	if _, err := finalImagePathWith(1, func(windows.Handle, *uint16, uint32, uint32) (uint32, error) {
		return 0, resolveError
	}); !errors.Is(err, resolveError) {
		t.Fatalf("resolve failure: %v", err)
	}
	calls := 0
	path, err := finalImagePathWith(1, func(_ windows.Handle, buffer *uint16, size, _ uint32) (uint32, error) {
		calls++
		if calls == 1 {
			return size + 16, nil
		}
		*buffer = 'X'
		return 1, nil
	})
	if err != nil || path != "X" || calls != 2 {
		t.Fatalf("path=%q calls=%d error=%v", path, calls, err)
	}
	if _, err := finalImagePathWith(1, func(_ windows.Handle, _ *uint16, size, _ uint32) (uint32, error) {
		return size, nil
	}); err == nil {
		t.Fatal("unstable resolved path size accepted")
	}
}

func TestValidateLocalImageStates(t *testing.T) {
	fixed := func(string) (uint32, error) { return windows.DRIVE_FIXED, nil }
	resolve := func(windows.Handle) (string, error) { return `\\?\C:\worker.exe`, nil }
	if err := validateLocalImageWith(`C:\worker.exe`, 1, fixed, resolve); err != nil {
		t.Fatalf("local worker: %v", err)
	}
	remote := func(string) (uint32, error) { return windows.DRIVE_REMOTE, nil }
	if err := validateLocalImageWith(`Z:\worker.exe`, 1, remote, resolve); err == nil {
		t.Fatal("remote configured worker accepted")
	}
	if err := validateLocalImageWith(`C:\worker.exe`, 1, func(string) (uint32, error) {
		return windows.DRIVE_UNKNOWN, errors.New("drive")
	}, resolve); err == nil {
		t.Fatal("configured drive failure accepted")
	}
	if err := validateLocalImageWith(`C:\worker.exe`, 1, fixed, func(windows.Handle) (string, error) {
		return "", errors.New("resolve")
	}); err == nil {
		t.Fatal("resolved path failure accepted")
	}
	resolvedDriveErr := errors.New("resolved drive")
	calls := 0
	err := validateLocalImageWith(`C:\worker.exe`, 1, func(string) (uint32, error) {
		calls++
		if calls == 1 {
			return windows.DRIVE_FIXED, nil
		}
		return windows.DRIVE_FIXED, resolvedDriveErr
	}, resolve)
	if !errors.Is(err, resolvedDriveErr) {
		t.Fatalf("resolved drive error lost: %v", err)
	}
	calls = 0
	if err := validateLocalImageWith(`C:\worker.exe`, 1, func(string) (uint32, error) {
		calls++
		if calls == 1 {
			return windows.DRIVE_FIXED, nil
		}
		return windows.DRIVE_REMOTE, nil
	}, resolve); err == nil {
		t.Fatal("remote resolved worker accepted")
	}
}

func TestValidLocalFinalPathRejectsNonCanonicalPath(t *testing.T) {
	if validLocalFinalPath(`C:\worker.exe`, windows.DRIVE_FIXED) {
		t.Fatal("path without native prefix accepted")
	}
	if validLocalFinalPath(`\\?\Z:\worker.exe`, windows.DRIVE_REMOTE) {
		t.Fatal("remote final path accepted")
	}
}
