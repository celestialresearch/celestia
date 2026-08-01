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
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validEvidenceRootPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 ||
		!asciiLetter(volume[0]) ||
		volume[1] != ':' {
		return false
	}
	return validEvidenceVolume(
		volume,
		windowsDriveType,
		windowsDeviceTarget,
	)
}

func asciiLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z'
}

type driveTypeLookup func(string) (uint32, error)

type deviceTargetLookup func(string) (string, error)

func validEvidenceVolume(
	volume string,
	driveType driveTypeLookup,
	deviceTarget deviceTargetLookup,
) bool {
	class, err := driveType(volume + `\`)
	if err != nil || class != windows.DRIVE_FIXED {
		return false
	}
	target, err := deviceTarget(volume)
	if err != nil {
		return false
	}
	return strings.HasPrefix(target, `\Device\HarddiskVolume`)
}

func windowsDriveType(root string) (uint32, error) {
	value, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0, err
	}
	return windows.GetDriveType(value), nil
}

func windowsDeviceTarget(volume string) (string, error) {
	device, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return "", err
	}
	var target [windows.MAX_PATH]uint16
	length, err := windows.QueryDosDevice(
		device,
		&target[0],
		windows.MAX_PATH,
	)
	if err != nil || length == 0 || length > windows.MAX_PATH {
		return "", err
	}
	return windows.UTF16ToString(target[:length]), nil
}
