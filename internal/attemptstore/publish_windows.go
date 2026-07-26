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
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const evidenceDirectoryAccess = windows.STANDARD_RIGHTS_ALL | 0x1ff

func publishFile(source, target, _ string) error {
	sourcePointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(
		sourcePointer,
		targetPointer,
		windows.MOVEFILE_WRITE_THROUGH,
	)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
		errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return ErrDuplicate
	}
	return err
}

func publishDirectory(source, target, _ string) error {
	return publishFile(source, target, "")
}

func secureEvidenceTree(path string) error {
	info, err := lstatEvidencePath(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || pathIsLinked(path, info) {
		return ErrCorrupt
	}
	if err := secureOwnedPath(path); err != nil {
		return err
	}
	return secureDirectoryACL(path)
}

func secureOwnedPath(path string) error {
	userSID, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(userSID) {
		return ErrCorrupt
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrCorrupt
	}
	return nil
}

func secureEvidenceFile(path string) error {
	if err := secureOwnedPath(path); err != nil {
		return err
	}
	if err := secureDirectoryACL(path); err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	var information windows.ByHandleFileInformation
	infoErr := windows.GetFileInformationByHandle(handle, &information)
	closeErr := windows.CloseHandle(handle)
	if err := errors.Join(infoErr, closeErr); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrCorrupt
	}
	return nil
}

func secureDirectoryACL(path string) error {
	userSID, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return ErrCorrupt
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil ||
		ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE ||
		ace.Mask != evidenceDirectoryAccess ||
		!evidenceACEIdentifies(ace, userSID) {
		return ErrCorrupt
	}
	return nil
}

func evidenceACEIdentifies(ace *windows.ACCESS_ALLOWED_ACE, expected *windows.SID) bool {
	const minimumSIDBytes = 8
	var layout windows.ACCESS_ALLOWED_ACE
	sidOffset := unsafe.Offsetof(layout.SidStart)
	if ace == nil ||
		expected == nil ||
		uintptr(ace.Header.AceSize) < sidOffset+minimumSIDBytes {
		return false
	}
	// GetAce exposes the variable-length SID through the fixed ACE prefix.
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // validated ACE bounds precede this Win32 SID conversion
	return aceSID.IsValid() &&
		uintptr(ace.Header.AceSize) == sidOffset+uintptr(aceSID.Len()) &&
		aceSID.Equals(expected)
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func secureDirectoryDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)", sid, sid),
	)
}

func createEvidenceDirectory(path string) error {
	descriptor, err := secureDirectoryDescriptor()
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pointer, &attributes); err != nil {
		return err
	}
	return secureEvidenceTree(path)
}

func pathIsLinked(path string, _ os.FileInfo) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return true
	}
	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func confirmPublication(directory string) error {
	return syncAttemptLockDirectory(directory)
}

func repairInterruptedRecords(path string) (err error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !recordTemporary(entry.Name()) {
			continue
		}
		info, err := root.Lstat(entry.Name())
		if err != nil ||
			invalidRecordFile(filepath.Join(path, entry.Name()), info) {
			return ErrCorrupt
		}
		if err := root.Remove(entry.Name()); err != nil {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return confirmPublication(path)
}
