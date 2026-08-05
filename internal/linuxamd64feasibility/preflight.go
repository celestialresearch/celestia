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
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	schemaVersion    = "celestia.linux-amd64-feasibility-preflight.v1"
	cgroupRoot       = "/sys/fs/cgroup"
	controllersPath  = cgroupRoot + "/cgroup.controllers"
	maxCgroupBytes   = 4 << 10
	maxRootBytes     = 4 << 10
	maxPlatformBytes = 32
	maxOutputBytes   = 512
)

type preflightResult struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	Platform      string `json:"platform"`
}

type preflightSource struct {
	goos       string
	goarch     string
	root       string
	absolute   func(string) bool
	read       func() ([]byte, error)
	lstat      func(string) (fs.FileMode, error)
	cgroupV2   func(string) (bool, error)
	filesystem func(string) (string, error)
}

// Probe returns one bounded canonical result. It does not start a process,
// modify the host or claim Linux feasibility.
func Probe(root string) []byte {
	return canonicalJSON(preflight(currentSource(root)))
}

func currentSource(root string) preflightSource {
	return preflightSource{
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		root:       root,
		absolute:   filepath.IsAbs,
		read:       readCgroupFile,
		lstat:      lstatMode,
		cgroupV2:   cgroupV2,
		filesystem: rootFilesystem,
	}
}

func preflight(source preflightSource) preflightResult {
	platform := platformName(source.goos, source.goarch)
	if source.goos != "linux" {
		return unavailable("wrong_os", platform)
	}
	if source.goarch != "amd64" {
		return unavailable("wrong_arch", platform)
	}
	if result, stop := inspectRoot(source, platform); stop {
		return result
	}
	if result, stop := inspectCgroup(source, platform); stop {
		return result
	}
	return indeterminate("native_controls_unverified", platform)
}

func inspectRoot(source preflightSource, platform string) (preflightResult, bool) {
	if len(source.root) == 0 || len(source.root) > maxRootBytes {
		return unavailable("evidence_root_invalid", platform), true
	}
	if !source.absolute(source.root) {
		return unavailable("evidence_root_not_absolute", platform), true
	}
	mode, err := source.lstat(source.root)
	if errors.Is(err, fs.ErrNotExist) {
		return unavailable("evidence_root_missing", platform), true
	}
	if err != nil {
		return indeterminate("evidence_root_indeterminate", platform), true
	}
	if mode&fs.ModeSymlink != 0 {
		return unavailable("evidence_root_symlink", platform), true
	}
	if !mode.IsDir() {
		return unavailable("evidence_root_not_directory", platform), true
	}
	filesystem, err := source.filesystem(source.root)
	if err != nil {
		return indeterminate("evidence_root_indeterminate", platform), true
	}
	if filesystem != "ext4" && filesystem != "xfs" {
		return unavailable("evidence_root_unsupported_filesystem", platform), true
	}
	return preflightResult{}, false
}

func inspectCgroup(source preflightSource, platform string) (preflightResult, bool) {
	v2, err := source.cgroupV2(cgroupRoot)
	if err != nil {
		return indeterminate("cgroup_v2_indeterminate", platform), true
	}
	if !v2 {
		return unavailable("cgroup_v2_missing", platform), true
	}
	controllers, err := source.read()
	if errors.Is(err, fs.ErrNotExist) {
		return unavailable("cgroup_v2_missing", platform), true
	}
	if err != nil {
		return indeterminate("cgroup_controllers_indeterminate", platform), true
	}
	if len(controllers) > maxCgroupBytes {
		return indeterminate("cgroup_controllers_oversized", platform), true
	}
	if !requiredControllers(controllers) {
		return indeterminate("cgroup_controllers_malformed", platform), true
	}
	for _, name := range []string{"cgroup.kill", "pids.max", "memory.max", "cpu.max"} {
		mode, err := source.lstat(cgroupRoot + "/" + name)
		if errors.Is(err, fs.ErrNotExist) {
			return unavailable("cgroup_delegation_missing", platform), true
		}
		if err != nil || mode&fs.ModeSymlink != 0 || !mode.IsRegular() {
			return indeterminate("cgroup_delegation_indeterminate", platform), true
		}
	}
	return preflightResult{}, false
}

func requiredControllers(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	controllers := map[string]bool{}
	for name := range strings.FieldsSeq(string(data)) {
		if strings.IndexFunc(name, func(character rune) bool {
			return unicode.IsControl(character) || character > unicode.MaxASCII
		}) >= 0 {
			return false
		}
		controllers[name] = true
	}
	return controllers["cpu"] && controllers["memory"] && controllers["pids"]
}

func unavailable(reason, platform string) preflightResult {
	return preflightResult{
		SchemaVersion: schemaVersion,
		Status:        "unavailable",
		Reason:        reason,
		Platform:      platform,
	}
}

func indeterminate(reason, platform string) preflightResult {
	return preflightResult{
		SchemaVersion: schemaVersion,
		Status:        "indeterminate",
		Reason:        reason,
		Platform:      platform,
	}
}

func platformName(goos, goarch string) string {
	if len(goos) == 0 || len(goarch) == 0 ||
		len(goos)+len(goarch)+1 > maxPlatformBytes ||
		!validPlatformPart(goos) || !validPlatformPart(goarch) {
		return "unknown"
	}
	return goos + "/" + goarch
}

func validPlatformPart(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return (character < 'a' || character > 'z') &&
			(character < '0' || character > '9')
	}) == -1
}

func canonicalJSON(result preflightResult) []byte {
	encoded, err := json.Marshal(result)
	if err != nil {
		panic("marshal fixed preflight result: " + err.Error())
	}
	return append(encoded, '\n')
}
