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

//go:build windows

package attemptstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSecureOwnedPathReportsNativeFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected owner validation failure")
	currentErr := secureOwnedPathFixture(failure, true)
	if !errors.Is(currentErr, failure) {
		t.Fatalf("current identity error = %v", currentErr)
	}
	controlErr := secureOwnedPathFixture(failure, false)
	if !errors.Is(controlErr, ErrCorrupt) {
		t.Fatalf("descriptor control error = %v", controlErr)
	}
}

func TestSecureOwnedPathRejectsInvalidOwner(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current SID: %v", err)
	}
	failure := errors.New("injected owner lookup failure")
	err = secureOwnedPathWith("unused", ownedPathOperations{
		current: func() (*windows.SID, error) { return sid, nil },
		descriptor: func(string) (*windows.SECURITY_DESCRIPTOR, error) {
			return &windows.SECURITY_DESCRIPTOR{}, nil
		},
		owner: func(*windows.SECURITY_DESCRIPTOR) (*windows.SID, error) {
			return sid, failure
		},
		control: func(
			*windows.SECURITY_DESCRIPTOR,
		) (windows.SECURITY_DESCRIPTOR_CONTROL, error) {
			return windows.SE_DACL_PROTECTED, nil
		},
	})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid owner accepted: %v", err)
	}
}

func TestSecureDirectoryACLRejectsInvalidDescriptor(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current SID: %v", err)
	}
	failure := errors.New("injected ACL failure")
	validACL := &windows.ACL{AceCount: 1}
	validACE := &windows.ACCESS_ALLOWED_ACE{}
	validACE.Header.AceType = windows.ACCESS_ALLOWED_ACE_TYPE
	tests := map[string]func(*aclOperations){
		"DACL error": func(operations *aclOperations) {
			operations.dacl = func(*windows.SECURITY_DESCRIPTOR) (*windows.ACL, error) {
				return nil, failure
			}
		},
		"ACE count": func(operations *aclOperations) {
			operations.dacl = func(*windows.SECURITY_DESCRIPTOR) (*windows.ACL, error) {
				return &windows.ACL{AceCount: 2}, nil
			}
		},
		"ACE error": func(operations *aclOperations) {
			operations.ace = func(*windows.ACL) (*windows.ACCESS_ALLOWED_ACE, error) {
				return nil, failure
			}
		},
		"ACE type": func(operations *aclOperations) {
			operations.ace = func(*windows.ACL) (*windows.ACCESS_ALLOWED_ACE, error) {
				ace := *validACE
				ace.Header.AceType = windows.ACCESS_DENIED_ACE_TYPE
				return &ace, nil
			}
		},
	}
	for name, replace := range tests {
		t.Run(name, func(t *testing.T) {
			operations := aclOperations{
				current: func() (*windows.SID, error) { return sid, nil },
				descriptor: func(string) (*windows.SECURITY_DESCRIPTOR, error) {
					return &windows.SECURITY_DESCRIPTOR{}, nil
				},
				dacl: func(*windows.SECURITY_DESCRIPTOR) (*windows.ACL, error) {
					return validACL, nil
				},
				ace: func(*windows.ACL) (*windows.ACCESS_ALLOWED_ACE, error) {
					return validACE, nil
				},
			}
			replace(&operations)
			if err := secureDirectoryACLWith(
				"unused",
				operations,
			); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid ACL accepted: %v", err)
			}
		})
	}
}

func secureOwnedPathFixture(failure error, failCurrent bool) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	operations := ownedPathOperations{
		current: func() (*windows.SID, error) { return sid, nil },
		descriptor: func(string) (*windows.SECURITY_DESCRIPTOR, error) {
			return &windows.SECURITY_DESCRIPTOR{}, nil
		},
		owner: func(*windows.SECURITY_DESCRIPTOR) (*windows.SID, error) {
			return sid, nil
		},
		control: func(
			*windows.SECURITY_DESCRIPTOR,
		) (windows.SECURITY_DESCRIPTOR_CONTROL, error) {
			return 0, failure
		},
	}
	if failCurrent {
		operations.current = func() (*windows.SID, error) {
			return nil, failure
		}
	}
	return secureOwnedPathWith("unused", operations)
}

func TestSecureEvidenceFileReportsNativeFailures(t *testing.T) {
	failure := errors.New("injected file validation failure")
	tests := []struct {
		name    string
		replace func(*evidenceFileOperations)
	}{
		{
			name: "encoding",
			replace: func(operations *evidenceFileOperations) {
				operations.encode = func(string) (*uint16, error) {
					return nil, failure
				}
			},
		},
		{
			name: "open",
			replace: func(operations *evidenceFileOperations) {
				operations.open = func(*uint16) (windows.Handle, error) {
					return 0, failure
				}
			},
		},
		{
			name: "inspection",
			replace: func(operations *evidenceFileOperations) {
				operations.inspect = func(
					windows.Handle,
				) (windows.ByHandleFileInformation, error) {
					return windows.ByHandleFileInformation{}, failure
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := testEvidenceFileOperations()
			test.replace(&operations)
			if err := secureEvidenceFileWith(
				"unused",
				operations,
			); !errors.Is(err, failure) {
				t.Fatalf("secureEvidenceFileWith() error = %v", err)
			}
		})
	}
}

func testEvidenceFileOperations() evidenceFileOperations {
	return evidenceFileOperations{
		owned: func(string) error { return nil },
		acl:   func(string) error { return nil },
		encode: func(string) (*uint16, error) {
			return new(uint16), nil
		},
		open: func(*uint16) (windows.Handle, error) { return 5, nil },
		inspect: func(
			windows.Handle,
		) (windows.ByHandleFileInformation, error) {
			return windows.ByHandleFileInformation{NumberOfLinks: 1}, nil
		},
		close: func(windows.Handle) error { return nil },
	}
}

func TestSecurityIdentityHelpersReportFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected identity failure")
	if err := secureDirectoryACLWith(
		"unused",
		aclOperations{
			current: func() (*windows.SID, error) { return nil, failure },
		},
	); !errors.Is(err, failure) {
		t.Fatalf("secureDirectoryACLWith() error = %v", err)
	}
	if _, err := currentUserSIDWith(
		func() (*windows.Tokenuser, error) { return nil, failure },
	); !errors.Is(err, failure) {
		t.Fatalf("currentUserSIDWith() error = %v", err)
	}
	if _, err := secureDirectoryDescriptorWith(
		func() (*windows.SID, error) { return nil, failure },
		windows.SecurityDescriptorFromString,
	); !errors.Is(err, failure) {
		t.Fatalf("secureDirectoryDescriptorWith() error = %v", err)
	}
}

func TestCreateEvidenceDirectoryReportsOwnedFailures(t *testing.T) {
	failure := errors.New("injected directory creation failure")
	tests := []struct {
		name    string
		replace func(*evidenceDirectoryOperations)
		removed bool
	}{
		{
			name: "descriptor",
			replace: func(operations *evidenceDirectoryOperations) {
				operations.descriptor = func() (*windows.SECURITY_DESCRIPTOR, error) {
					return nil, failure
				}
			},
		},
		{
			name: "security validation",
			replace: func(operations *evidenceDirectoryOperations) {
				operations.secure = func(string) error { return failure }
			},
			removed: true,
		},
		{
			name: "parent synchronisation",
			replace: func(operations *evidenceDirectoryOperations) {
				operations.sync = func(string) error { return failure }
			},
			removed: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			removed := false
			operations := testEvidenceDirectoryOperations()
			operations.remove = func(string, string) error {
				removed = true
				return nil
			}
			test.replace(&operations)
			err := createEvidenceDirectoryWith("C:\\evidence", operations)
			if !errors.Is(err, failure) || removed != test.removed {
				t.Fatalf("error = %v, removed = %t", err, removed)
			}
		})
	}
}

func testEvidenceDirectoryOperations() evidenceDirectoryOperations {
	return evidenceDirectoryOperations{
		descriptor: func() (*windows.SECURITY_DESCRIPTOR, error) {
			return &windows.SECURITY_DESCRIPTOR{}, nil
		},
		encode: func(string) (*uint16, error) { return new(uint16), nil },
		create: func(*uint16, *windows.SecurityAttributes) error { return nil },
		secure: func(string) error { return nil },
		remove: func(string, string) error { return nil },
		sync:   func(string) error { return nil },
	}
}

func TestRemoveCreatedDirectoryReportsMissingParent(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "missing")
	if err := removeCreatedDirectory(
		filepath.Join(parent, "child"),
		parent,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removeCreatedDirectory() error = %v", err)
	}
}

func TestRepairInterruptedRecordsReportsOpenFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected repair open failure")
	operations := testRecordRepairOperations()
	operations.openRoot = func(string) (*os.Root, error) {
		return nil, failure
	}
	if err := repairInterruptedRecordsWith(
		t.TempDir(),
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("open-root error = %v", err)
	}

	operations = testRecordRepairOperations()
	operations.openDirectory = func(*os.Root, string) (*os.File, error) {
		return nil, failure
	}
	if err := repairInterruptedRecordsWith(
		t.TempDir(),
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("open-directory error = %v", err)
	}
}

func TestRepairInterruptedRecordsReportsReadFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected repair read failure")
	operations := testRecordRepairOperations()
	operations.readDirectory = func(*os.File) ([]os.DirEntry, error) {
		return nil, failure
	}
	if err := repairInterruptedRecordsWith(
		t.TempDir(),
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("repairInterruptedRecordsWith() error = %v", err)
	}
}

func TestRepairInterruptedRecordsReportsRemoveFailure(t *testing.T) {
	t.Parallel()

	path := protectedTestDirectory(t)
	file, err := createRecordTemp(path, admittedFile)
	if err != nil {
		t.Fatalf("create temporary fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary fixture: %v", err)
	}
	failure := errors.New("injected repair removal failure")
	operations := testRecordRepairOperations()
	operations.remove = func(*os.Root, string) error { return failure }
	if err := repairInterruptedRecordsWith(
		path,
		operations,
	); !errors.Is(err, failure) {
		t.Fatalf("repairInterruptedRecordsWith() error = %v", err)
	}
}

func TestRepairInterruptedRecordsHandlesEmptyAndUninspectableEntries(t *testing.T) {
	path := protectedTestDirectory(t)
	operations := testRecordRepairOperations()
	removed := false
	confirmed := false
	operations.readDirectory = func(*os.File) ([]os.DirEntry, error) {
		return []os.DirEntry{}, nil
	}
	operations.remove = func(*os.Root, string) error {
		removed = true
		return nil
	}
	operations.confirm = func(string) error {
		confirmed = true
		return nil
	}
	if err := repairInterruptedRecordsWith(path, operations); err != nil {
		t.Fatalf("empty repair: %v", err)
	}
	if removed || confirmed {
		t.Fatalf("empty repair removed=%t confirmed=%t", removed, confirmed)
	}

	file, err := createRecordTemp(path, admittedFile)
	if err != nil {
		t.Fatalf("create temporary: %v", err)
	}
	name := filepath.Base(file.Name())
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary: %v", err)
	}
	operations = testRecordRepairOperations()
	operations.lstat = func(*os.Root, string) (os.FileInfo, error) {
		return nil, errors.New("injected temporary inspection failure")
	}
	if err := repairInterruptedRecordsWith(path, operations); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("uninspectable %s returned %v", name, err)
	}
}

func testRecordRepairOperations() recordRepairOperations {
	return recordRepairOperations{
		openRoot:  os.OpenRoot,
		closeRoot: (*os.Root).Close,
		openDirectory: func(root *os.Root, name string) (*os.File, error) {
			return root.Open(name)
		},
		readDirectory: func(directory *os.File) ([]os.DirEntry, error) {
			return directory.ReadDir(-1)
		},
		closeFile: (*os.File).Close,
		lstat: func(root *os.Root, name string) (os.FileInfo, error) {
			return root.Lstat(name)
		},
		invalid: invalidRecordFile,
		remove: func(root *os.Root, name string) error {
			return root.Remove(name)
		},
		confirm: confirmPublication,
	}
}

func TestPublishedAttemptDirectoryIsStable(t *testing.T) {
	attempt := &Attempt{path: `C:\evidence\attempt`}
	path, err := attempt.publishDirectory()
	if err != nil || path != attempt.path {
		t.Fatalf("publishDirectory() path = %q, error = %v", path, err)
	}
}

func TestAttemptPreparationRejectsPublishedIdentity(t *testing.T) {
	store := newTestStore(t)
	accepted, _ := testAccepted(t)
	if err := createEvidenceDirectory(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("create published fixture: %v", err)
	}
	if _, _, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		createEvidenceDirectory,
	); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("prepareAttemptDirectories() error = %v, want %v", err, ErrDuplicate)
	}
}

func TestAttemptPreparationRejectsInvalidRoot(t *testing.T) {
	accepted, _ := testAccepted(t)
	store := &Store{root: "invalid\x00root"}
	if _, _, err := store.prepareAttemptDirectories(
		accepted.Request.AttemptID,
		createEvidenceDirectory,
	); err == nil {
		t.Fatal("invalid attempt root accepted")
	}
}

func TestPublishPendingDirectoryRejectsExistingTarget(t *testing.T) {
	parent := protectedTestDirectory(t)
	source := filepath.Join(parent, "source")
	target := filepath.Join(parent, "target")
	for _, path := range []string{source, target} {
		if err := createEvidenceDirectory(path); err != nil {
			t.Fatalf("create %s: %v", filepath.Base(path), err)
		}
	}
	if _, err := publishPendingDirectory(source, target, parent); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("publishPendingDirectory() error = %v, want %v", err, ErrDuplicate)
	}
}

func TestRemovePendingDirectoryRejectsInvalidState(t *testing.T) {
	t.Run("non-directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pending")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write pending fixture: %v", err)
		}
		if err := removePendingDirectory(path); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("removePendingDirectory() error = %v, want %v", err, ErrCorrupt)
		}
	})

	t.Run("non-empty directory", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "owned")
		if err := createEvidenceDirectory(parent); err != nil {
			t.Fatalf("create protected parent: %v", err)
		}
		path := filepath.Join(parent, "pending")
		if err := createEvidenceDirectory(path); err != nil {
			t.Fatalf("create pending directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "record"), nil, 0o600); err != nil {
			t.Fatalf("write pending record: %v", err)
		}
		if err := removePendingDirectory(path); err == nil {
			t.Fatal("removePendingDirectory() removed a non-empty directory")
		}
	})
}

func TestReceiptCreationRequiresBothRecords(t *testing.T) {
	path := protectedTestDirectory(t)
	accepted, _ := testAccepted(t)
	if err := writeOrMatchReceipt(
		path,
		accepted.Request.AttemptID,
		"observation",
		observationFile,
		"verified",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writeOrMatchReceipt() error = %v, want missing record", err)
	}
}

func TestPublicationRequiresReceipt(t *testing.T) {
	path := protectedTestDirectory(t)
	accepted, _ := testAccepted(t)
	if err := publishMarker(path, accepted.Request.AttemptID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publishMarker() error = %v, want missing receipt", err)
	}
}

func TestPublishDirectoryRetainsCleanupFailure(t *testing.T) {
	t.Parallel()

	accepted, _ := testAccepted(t)
	failure := errors.New("injected pending cleanup failure")
	attempt := &Attempt{
		store:       &Store{root: `C:\evidence`},
		path:        `C:\evidence\pending\attempt`,
		pendingPath: `C:\evidence\pending`,
		admitted:    Admitted{AttemptID: accepted.Request.AttemptID},
	}
	path, err := attempt.publishDirectoryWith(pendingPublicationOperations{
		publish: func(string, string, string) (string, error) {
			return `C:\evidence\attempts\attempt`, nil
		},
		remove: func(string) error { return failure },
	})
	if path != "" || !errors.Is(err, failure) ||
		attempt.pendingPath != "" {
		t.Fatalf(
			"path = %q, error = %v, pending = %q",
			path,
			err,
			attempt.pendingPath,
		)
	}
}

func TestRemovePendingReportsSecurityFailure(t *testing.T) {
	t.Parallel()

	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	failure := errors.New("injected pending security failure")
	err = removePendingDirectoryWith(
		"unused",
		pendingRemovalOperations{
			lstat:  func(string) (os.FileInfo, error) { return info, nil },
			linked: func(string, os.FileInfo) bool { return false },
			secure: func(string) error { return failure },
			remove: func(string) error {
				t.Fatal("remove called after security failure")
				return nil
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("removePendingDirectoryWith() error = %v", err)
	}
}

func TestPublishMarkerReportsWriteFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected marker write failure")
	err := publishMarkerWith(
		"unused",
		"attempt",
		markerPublicationOperations{
			read: func(string, string) (Records, error) {
				return Records{
					Receipt:     Receipt{TerminalFile: observationFile},
					receiptHash: strings.Repeat("a", 64),
				}, nil
			},
			validate: func(string, string, bool) error { return nil },
			write: func(string, string, any) error {
				return failure
			},
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("publishMarkerWith() error = %v", err)
	}
}

func TestPublishRejectsConflictingReceipt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	conflict := Receipt{
		Version:       Version,
		AttemptID:     accepted.Request.AttemptID,
		TerminalKind:  "recovery",
		AdmittedFile:  admittedFile,
		AdmittedHash:  strings.Repeat("a", 64),
		TerminalFile:  recoveryFile,
		TerminalHash:  strings.Repeat("b", 64),
		TerminalState: "indeterminate",
	}
	if err := writeRecord(attempt.path, receiptFile, conflict); err != nil {
		t.Fatalf("write conflicting receipt: %v", err)
	}
	err = attempt.Publish(testObservationFor(t, accepted))
	if !errors.Is(err, ErrPublication) || !errors.Is(err, ErrDuplicate) {
		t.Fatalf("conflicting receipt accepted: %v", err)
	}
}

func TestPublishRejectsFinalDirectoryCollision(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := createEvidenceDirectory(store.finalPath(accepted.Request.AttemptID)); err != nil {
		t.Fatalf("create final collision: %v", err)
	}
	err = attempt.Publish(testObservationFor(t, accepted))
	if !errors.Is(err, ErrPublication) || !errors.Is(err, ErrDuplicate) {
		t.Fatalf("final collision accepted: %v", err)
	}
}

func TestRemovePendingRejectsInvalidPath(t *testing.T) {
	if err := removePendingDirectory("invalid\x00path"); err == nil {
		t.Fatal("invalid pending path accepted")
	}
}
