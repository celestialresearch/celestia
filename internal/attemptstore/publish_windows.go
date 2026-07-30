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

type evidenceDirectoryOperations struct {
	descriptor func() (*windows.SECURITY_DESCRIPTOR, error)
	encode     func(string) (*uint16, error)
	create     func(*uint16, *windows.SecurityAttributes) error
	secure     func(string) error
	remove     func(string, string) error
	sync       func(string) error
}

type recordRepairOperations struct {
	openRoot      func(string) (*os.Root, error)
	closeRoot     func(*os.Root) error
	openDirectory func(*os.Root, string) (*os.File, error)
	readDirectory func(*os.File) ([]os.DirEntry, error)
	closeFile     func(*os.File) error
	lstat         func(*os.Root, string) (os.FileInfo, error)
	invalid       func(string, os.FileInfo) bool
	remove        func(*os.Root, string) error
	confirm       func(string) error
}

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

func createEvidenceDirectory(path string) error {
	return createEvidenceDirectoryWith(
		path,
		evidenceDirectoryOperations{
			descriptor: secureDirectoryDescriptor,
			encode:     windows.UTF16PtrFromString,
			create:     windows.CreateDirectory,
			secure:     secureEvidenceTree,
			remove:     removeCreatedDirectory,
			sync:       syncDirectory,
		},
	)
}

func createEvidenceDirectoryWith(
	path string,
	operations evidenceDirectoryOperations,
) error {
	parent := filepath.Dir(path)
	descriptor, err := operations.descriptor()
	if err != nil {
		return err
	}
	pointer, err := operations.encode(filepath.Clean(path))
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := operations.create(pointer, &attributes); err != nil {
		return err
	}
	if err := operations.secure(path); err != nil {
		return errors.Join(err, operations.remove(path, parent))
	}
	if err := operations.sync(parent); err != nil {
		return errors.Join(err, operations.remove(path, parent))
	}
	return nil
}

func removeCreatedDirectory(path, parent string) error {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	removeErr := root.Remove(filepath.Base(path))
	closeErr := root.Close()
	return errors.Join(removeErr, closeErr, syncDirectory(parent))
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

func syncDirectory(directory string) error {
	return syncAttemptLockDirectory(directory)
}

func repairInterruptedRecords(path string) (err error) {
	return repairInterruptedRecordsWith(
		path,
		recordRepairOperations{
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
		},
	)
}

func repairInterruptedRecordsWith(
	path string,
	operations recordRepairOperations,
) (err error) {
	root, err := operations.openRoot(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, operations.closeRoot(root))
	}()
	directory, err := operations.openDirectory(root, ".")
	if err != nil {
		return err
	}
	entries, readErr := operations.readDirectory(directory)
	closeErr := operations.closeFile(directory)
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !recordTemporary(entry.Name()) {
			continue
		}
		info, err := operations.lstat(root, entry.Name())
		if err != nil ||
			operations.invalid(filepath.Join(path, entry.Name()), info) {
			return ErrCorrupt
		}
		if err := operations.remove(root, entry.Name()); err != nil {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return operations.confirm(path)
}

func recordTemporary(candidate string) bool {
	for _, record := range recordNames() {
		if temporaryRecordName(record, candidate) {
			return true
		}
	}
	return false
}
