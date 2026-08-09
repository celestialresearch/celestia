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

package filereplace

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func sameRoot(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func secureTargetRoot(path string) (string, error) {
	clean := filepath.Clean(path)
	if !validFixedTargetRoot(path, clean) {
		return "", ErrTarget
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrTarget
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		clean, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	if !ownedProtectedTargetRoot(descriptor) {
		return "", ErrTarget
	}
	return clean, nil
}

func ownedProtectedTargetRoot(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	if descriptor == nil {
		return false
	}
	owner, _, ownerErr := descriptor.Owner()
	control, _, controlErr := descriptor.Control()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if ownerErr != nil || controlErr != nil || userErr != nil || owner == nil ||
		!owner.Equals(user.User.Sid) || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	if !exclusiveTargetDACL(descriptor, user.User.Sid) {
		return false
	}
	return true
}

func validFixedTargetRoot(original, clean string) bool {
	volume := filepath.VolumeName(clean)
	if original == "" || !filepath.IsAbs(clean) || len(volume) != 2 || volume[1] != ':' {
		return false
	}
	pointer, err := windows.UTF16PtrFromString(volume + `\`)
	return err == nil && windows.GetDriveType(pointer) == windows.DRIVE_FIXED
}

func exclusiveTargetDACL(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) bool {
	if descriptor == nil || user == nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE ||
		ace.Mask != windows.STANDARD_RIGHTS_ALL|0x1ff ||
		uintptr(ace.Header.AceSize) < unsafe.Offsetof(ace.SidStart)+8 {
		return false
	}
	return allowedACESID(ace, user)
}

func secureTargetHandle(file *os.File) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()), &information,
	); err != nil {
		return err
	}
	if !validTargetFileInformation(information) {
		return ErrTarget
	}
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || !ownedExclusiveTarget(descriptor) {
		return ErrTarget
	}
	return nil
}

func validTargetFileInformation(information windows.ByHandleFileInformation) bool {
	return information.NumberOfLinks == 1 &&
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 &&
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func ownedExclusiveTarget(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	if descriptor == nil {
		return false
	}
	owner, _, ownerErr := descriptor.Owner()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if ownerErr != nil || userErr != nil || owner == nil || !owner.Equals(user.User.Sid) {
		return false
	}
	return exclusiveTargetFileDACL(descriptor, user.User.Sid)
}

func exclusiveTargetFileDACL(
	descriptor *windows.SECURITY_DESCRIPTOR,
	user *windows.SID,
) bool {
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Mask != windows.STANDARD_RIGHTS_ALL|0x1ff ||
		uintptr(ace.Header.AceSize) < unsafe.Offsetof(ace.SidStart)+8 {
		return false
	}
	return allowedACESID(ace, user)
}

func allowedACESID(ace *windows.ACCESS_ALLOWED_ACE, user *windows.SID) bool {
	// GetAce exposes the validated variable-length SID through the ACE prefix.
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- Win32 ACE layout requires this conversion.
	return sid.IsValid() && uintptr(sid.Len()) <=
		uintptr(ace.Header.AceSize)-unsafe.Offsetof(ace.SidStart) && sid.Equals(user)
}

func openTargetDirectory(path string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH, 0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func syncTargetDirectory(directory *os.File) error {
	if directory == nil {
		return ErrTarget
	}
	return windows.FlushFileBuffers(windows.Handle(directory.Fd()))
}
