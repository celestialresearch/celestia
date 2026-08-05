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
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

const evidenceDirectoryAccess = windows.STANDARD_RIGHTS_ALL | 0x1ff

type ownedPathOperations struct {
	current    func() (*windows.SID, error)
	descriptor func(string) (*windows.SECURITY_DESCRIPTOR, error)
	owner      func(*windows.SECURITY_DESCRIPTOR) (*windows.SID, error)
	control    func(*windows.SECURITY_DESCRIPTOR) (windows.SECURITY_DESCRIPTOR_CONTROL, error)
}

type evidenceFileOperations struct {
	owned   func(string) error
	acl     func(string) error
	encode  func(string) (*uint16, error)
	open    func(*uint16) (windows.Handle, error)
	inspect func(windows.Handle) (windows.ByHandleFileInformation, error)
	close   func(windows.Handle) error
}

type aclOperations struct {
	current    func() (*windows.SID, error)
	descriptor func(string) (*windows.SECURITY_DESCRIPTOR, error)
	dacl       func(*windows.SECURITY_DESCRIPTOR) (*windows.ACL, error)
	ace        func(*windows.ACL) (*windows.ACCESS_ALLOWED_ACE, error)
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
	return secureOwnedPathWith(
		path,
		ownedPathOperations{
			current: currentUserSID,
			descriptor: func(path string) (*windows.SECURITY_DESCRIPTOR, error) {
				return windows.GetNamedSecurityInfo(
					path,
					windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|
						windows.DACL_SECURITY_INFORMATION,
				)
			},
			owner: func(
				descriptor *windows.SECURITY_DESCRIPTOR,
			) (*windows.SID, error) {
				owner, _, err := descriptor.Owner()
				return owner, err
			},
			control: func(
				descriptor *windows.SECURITY_DESCRIPTOR,
			) (windows.SECURITY_DESCRIPTOR_CONTROL, error) {
				control, _, err := descriptor.Control()
				return control, err
			},
		},
	)
}

func secureOwnedPathWith(
	path string,
	operations ownedPathOperations,
) error {
	userSID, err := operations.current()
	if err != nil {
		return err
	}
	descriptor, err := operations.descriptor(path)
	if err != nil {
		return err
	}
	owner, err := operations.owner(descriptor)
	if err != nil || owner == nil || !owner.Equals(userSID) {
		return ErrCorrupt
	}
	control, err := operations.control(descriptor)
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrCorrupt
	}
	return nil
}

func secureEvidenceFile(path string) error {
	return secureEvidenceFileWith(
		path,
		evidenceFileOperations{
			owned:  secureOwnedPath,
			acl:    secureDirectoryACL,
			encode: windows.UTF16PtrFromString,
			open: func(pointer *uint16) (windows.Handle, error) {
				return windows.CreateFile(
					pointer,
					windows.GENERIC_READ,
					windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
					nil,
					windows.OPEN_EXISTING,
					windows.FILE_ATTRIBUTE_NORMAL|
						windows.FILE_FLAG_OPEN_REPARSE_POINT,
					0,
				)
			},
			inspect: func(
				handle windows.Handle,
			) (windows.ByHandleFileInformation, error) {
				var information windows.ByHandleFileInformation
				err := windows.GetFileInformationByHandle(handle, &information)
				return information, err
			},
			close: windows.CloseHandle,
		},
	)
}

func secureEvidenceFileWith(
	path string,
	operations evidenceFileOperations,
) error {
	if err := operations.owned(path); err != nil {
		return err
	}
	if err := operations.acl(path); err != nil {
		return err
	}
	pointer, err := operations.encode(path)
	if err != nil {
		return err
	}
	handle, err := operations.open(pointer)
	if err != nil {
		return err
	}
	information, infoErr := operations.inspect(handle)
	closeErr := operations.close(handle)
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
	return secureDirectoryACLWith(
		path,
		aclOperations{
			current: currentUserSID,
			descriptor: func(path string) (*windows.SECURITY_DESCRIPTOR, error) {
				return windows.GetNamedSecurityInfo(
					path,
					windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION,
				)
			},
			dacl: func(
				descriptor *windows.SECURITY_DESCRIPTOR,
			) (*windows.ACL, error) {
				dacl, _, err := descriptor.DACL()
				return dacl, err
			},
			ace: func(dacl *windows.ACL) (*windows.ACCESS_ALLOWED_ACE, error) {
				var ace *windows.ACCESS_ALLOWED_ACE
				err := windows.GetAce(dacl, 0, &ace)
				return ace, err
			},
		},
	)
}

func secureDirectoryACLWith(
	path string,
	operations aclOperations,
) error {
	userSID, err := operations.current()
	if err != nil {
		return err
	}
	descriptor, err := operations.descriptor(path)
	if err != nil {
		return err
	}
	dacl, err := operations.dacl(descriptor)
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return ErrCorrupt
	}
	ace, err := operations.ace(dacl)
	if err != nil ||
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
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- validated ACE bounds precede this Win32 SID conversion.
	return aceSID.IsValid() &&
		uintptr(ace.Header.AceSize) == sidOffset+uintptr(aceSID.Len()) &&
		aceSID.Equals(expected)
}

func currentUserSID() (*windows.SID, error) {
	return currentUserSIDWith(func() (*windows.Tokenuser, error) {
		return windows.GetCurrentProcessToken().GetTokenUser()
	})
}

func currentUserSIDWith(
	current func() (*windows.Tokenuser, error),
) (*windows.SID, error) {
	user, err := current()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func secureDirectoryDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return secureDirectoryDescriptorWith(
		currentUserSID,
		windows.SecurityDescriptorFromString,
	)
}

func ownedSecurityAttributes(
	descriptor *windows.SECURITY_DESCRIPTOR,
) windows.SecurityAttributes {
	return windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
}

func secureDirectoryDescriptorWith(
	current func() (*windows.SID, error),
	parse func(string) (*windows.SECURITY_DESCRIPTOR, error),
) (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := current()
	if err != nil {
		return nil, err
	}
	return parse(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)", sid, sid),
	)
}
