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
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEvidenceRootPathPolicy(t *testing.T) {
	tests := map[string]struct {
		path string
		want bool
	}{
		"local":    {path: filepath.Join(t.TempDir(), "evidence"), want: true},
		"relative": {path: "evidence"},
		"UNC":      {path: `\\invalid.example\share\evidence`},
		"device":   {path: `\\?\C:\evidence`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := validEvidenceRootPath(test.path); actual != test.want {
				t.Fatalf("validEvidenceRootPath(%q) = %t, want %t", test.path, actual, test.want)
			}
		})
	}
}

func TestEvidenceVolumePolicy(t *testing.T) {
	tests := []struct {
		name      string
		driveType uint32
		target    string
		targetErr error
		want      bool
	}{
		{name: "fixed local volume", driveType: windows.DRIVE_FIXED, target: `\Device\HarddiskVolume3`, want: true},
		{name: "mapped remote", driveType: windows.DRIVE_REMOTE, target: `\Device\Mup\server\share`},
		{name: "substituted drive", driveType: windows.DRIVE_FIXED, target: `\??\C:\evidence`},
		{name: "removable drive", driveType: windows.DRIVE_REMOVABLE, target: `\Device\HarddiskVolume4`},
		{name: "RAM disk", driveType: windows.DRIVE_RAMDISK, target: `\Device\HarddiskVolume5`},
		{name: "unknown drive", driveType: windows.DRIVE_UNKNOWN},
		{name: "missing root", driveType: windows.DRIVE_NO_ROOT_DIR},
		{name: "lookup failure", driveType: windows.DRIVE_FIXED, targetErr: errors.New("lookup failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driveType := func(string) (uint32, error) {
				return test.driveType, nil
			}
			deviceTarget := func(string) (string, error) {
				if test.targetErr != nil {
					return "", test.targetErr
				}
				return test.target, nil
			}
			if actual := validEvidenceVolume("C:", driveType, deviceTarget); actual != test.want {
				t.Fatalf("validEvidenceVolume() = %t, want %t", actual, test.want)
			}
		})
	}
}

func TestWindowsVolumeLookupsFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := windowsDriveType("C:\x00\\"); err == nil {
		t.Fatal("windowsDriveType() accepted an embedded NUL")
	}
	if _, err := windowsDeviceTarget("C:\x00"); err == nil {
		t.Fatal("windowsDeviceTarget() accepted an embedded NUL")
	}
	if _, err := windowsDeviceTarget("?:"); err == nil {
		t.Fatal("windowsDeviceTarget() accepted a nonexistent DOS device")
	}
}
