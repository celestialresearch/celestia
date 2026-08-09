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

package attempt

import (
	"encoding/hex"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileIDInformation struct {
	VolumeSerial uint64
	FileID       [16]byte
}

func IdentifyRoot(directory *os.File) (RootIdentity, error) {
	if directory == nil {
		return RootIdentity{}, ErrCorrupt
	}
	var information fileIDInformation
	err := windows.GetFileInformationByHandleEx(
		windows.Handle(directory.Fd()), windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&information)), // #nosec G103 -- Win32 writes FILE_ID_INFO into the fixed layout.
		uint32(unsafe.Sizeof(information)),
	)
	if err != nil {
		return RootIdentity{}, err
	}
	return RootIdentity{
		VolumeSerial: information.VolumeSerial,
		FileID:       hex.EncodeToString(information.FileID[:]),
	}, nil
}

func validRootIdentity(identity RootIdentity) bool {
	if len(identity.FileID) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(identity.FileID)
	return err == nil && hex.EncodeToString(decoded) == identity.FileID
}
