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

package linuxamd64feasibility

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightRefusesUnavailablePrerequisites(t *testing.T) {
	cases := append(platformRefusalCases(), rootRefusalCases()...)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := preflight(test.source)
			if result.Status != test.status || result.Reason != test.reason {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

type preflightCase struct {
	name   string
	source preflightSource
	status string
	reason string
}

func platformRefusalCases() []preflightCase {
	return []preflightCase{
		{
			name:   "wrong OS",
			source: readySource("windows", "amd64"),
			status: "unavailable",
			reason: "wrong_os",
		},
		{
			name:   "wrong architecture",
			source: readySource("linux", "arm64"),
			status: "unavailable",
			reason: "wrong_arch",
		},
		{
			name: "missing cgroup v2",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.cgroupV2 = func(string) (bool, error) { return false, nil }
			}),
			status: "unavailable",
			reason: "cgroup_v2_missing",
		},
		{
			name: "missing cgroup delegation",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.lstat = func(name string) (fs.FileMode, error) {
					if name == "/sys/fs/cgroup/cgroup.kill" {
						return 0, fs.ErrNotExist
					}
					return modeFor(name), nil
				}
			}),
			status: "unavailable",
			reason: "cgroup_delegation_missing",
		},
	}
}

func rootRefusalCases() []preflightCase {
	return []preflightCase{
		{
			name: "unsupported evidence filesystem",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.filesystem = func(string) (string, error) { return "overlay", nil }
			}),
			status: "unavailable",
			reason: "evidence_root_unsupported_filesystem",
		},
		{
			name: "relative evidence root",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.root = "relative"
				source.absolute = func(string) bool { return false }
			}),
			status: "unavailable",
			reason: "evidence_root_not_absolute",
		},
		{
			name: "missing evidence root",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.lstat = func(string) (fs.FileMode, error) { return 0, fs.ErrNotExist }
			}),
			status: "unavailable",
			reason: "evidence_root_missing",
		},
		{
			name: "non-directory evidence root",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.lstat = func(name string) (fs.FileMode, error) {
					if name == "/evidence" {
						return 0, nil
					}
					return modeFor(name), nil
				}
			}),
			status: "unavailable",
			reason: "evidence_root_not_directory",
		},
		{
			name: "symbolic-link evidence root",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.lstat = func(name string) (fs.FileMode, error) {
					if name == "/evidence" {
						return fs.ModeSymlink, nil
					}
					return modeFor(name), nil
				}
			}),
			status: "unavailable",
			reason: "evidence_root_symlink",
		},
	}
}

func TestPreflightRemainsIndeterminate(t *testing.T) {
	cases := append(cgroupIndeterminateCases(), rootIndeterminateCases()...)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := preflight(test.source)
			if result.Status != "indeterminate" || result.Reason != test.reason {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func cgroupIndeterminateCases() []preflightCase {
	return []preflightCase{
		{
			name:   "unverified native controls",
			source: readySource("linux", "amd64"),
			reason: "native_controls_unverified",
		},
		{
			name: "malformed controllers",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.read = sourceRead("cpu\x00memory pids")
			}),
			reason: "cgroup_controllers_malformed",
		},
		{
			name: "oversized controllers",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.read = sourceRead(strings.Repeat("a", maxCgroupBytes+1))
			}),
			reason: "cgroup_controllers_oversized",
		},
		{
			name: "cgroup statfs error",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.cgroupV2 = func(string) (bool, error) { return false, errors.New("inspect") }
			}),
			reason: "cgroup_v2_indeterminate",
		},
		{
			name: "cgroup control read error",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.read = func() ([]byte, error) {
					return nil, errors.New("read")
				}
			}),
			reason: "cgroup_controllers_indeterminate",
		},
		{
			name: "cgroup control lstat error",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.lstat = func(name string) (fs.FileMode, error) {
					if strings.HasSuffix(name, "cgroup.kill") {
						return 0, errors.New("stat")
					}
					return modeFor(name), nil
				}
			}),
			reason: "cgroup_delegation_indeterminate",
		},
	}
}

func rootIndeterminateCases() []preflightCase {
	return []preflightCase{
		{
			name: "evidence root lstat error",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.lstat = func(name string) (fs.FileMode, error) {
					if name == "/evidence" {
						return 0, errors.New("stat")
					}
					return modeFor(name), nil
				}
			}),
			reason: "evidence_root_indeterminate",
		},
		{
			name: "evidence filesystem statfs error",
			source: sourceWith(readySource("linux", "amd64"), func(source *preflightSource) {
				source.filesystem = func(string) (string, error) { return "", errors.New("statfs") }
			}),
			reason: "evidence_root_indeterminate",
		},
	}
}

func TestPreflightCanonicalJSONIsBounded(t *testing.T) {
	source := readySource(strings.Repeat("x", maxPlatformBytes+1), "amd64")
	encoded := canonicalJSON(preflight(source))
	if len(encoded) > maxOutputBytes ||
		string(encoded) != "{\"schema_version\":\"celestia.linux-amd64-feasibility-preflight.v1\",\"status\":\"unavailable\",\"reason\":\"wrong_os\",\"platform\":\"unknown\"}\n" {
		t.Fatalf("encoded=%q", encoded)
	}
}

func TestProbeEmitsTerminalJSON(t *testing.T) {
	encoded := Probe(t.TempDir())
	var result preflightResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatalf("decode probe result: %v", err)
	}
	if result.SchemaVersion != schemaVersion ||
		(result.Status != "unavailable" && result.Status != "indeterminate") ||
		result.Reason == "" || len(encoded) > maxOutputBytes {
		t.Fatalf("result=%+v", result)
	}
}

func TestHostReadersBoundAndClassifyFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	data, err := readBounded(strings.NewReader("content"))
	if err != nil || string(data) != "content" {
		t.Fatalf("read data=%q err=%v", data, err)
	}
	mode, err := lstatMode(path)
	if err != nil || !mode.IsRegular() {
		t.Fatalf("mode=%v err=%v", mode, err)
	}
}

func readySource(goos, goarch string) preflightSource {
	return preflightSource{
		goos:     goos,
		goarch:   goarch,
		root:     "/evidence",
		absolute: func(string) bool { return true },
		read:     sourceRead(readyControllers()),
		lstat: func(name string) (fs.FileMode, error) {
			return modeFor(name), nil
		},
		cgroupV2:   func(string) (bool, error) { return true, nil },
		filesystem: func(string) (string, error) { return "ext4", nil },
	}
}

func sourceRead(controllers string) func() ([]byte, error) {
	return func() ([]byte, error) {
		return []byte(controllers), nil
	}
}

func readyControllers() string {
	return "cpu memory pids\n"
}

func modeFor(name string) fs.FileMode {
	if name == "/evidence" {
		return fs.ModeDir
	}
	return 0
}

func sourceWith(source preflightSource, change func(*preflightSource)) preflightSource {
	change(&source)
	return source
}
