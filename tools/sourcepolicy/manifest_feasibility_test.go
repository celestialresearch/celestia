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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

type linuxFeasibilityManifest struct {
	SliceID        string           `json:"slice_id"`
	Owner          string           `json:"owner"`
	CanonicalState []string         `json:"canonical_state"`
	NonGoals       []string         `json:"non_goals"`
	Platforms      []linuxPlatform  `json:"platforms"`
	Invariants     []linuxInvariant `json:"invariants"`
	Resources      []linuxResource  `json:"resources"`
}

type linuxPlatform struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Support string `json:"support"`
}

type linuxInvariant struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type linuxResource struct {
	Kind        string `json:"kind"`
	Acquisition string `json:"acquisition"`
	Release     string `json:"release"`
}

func TestLinuxAMD64FeasibilityManifestPreservesQualificationBoundary(t *testing.T) {
	t.Chdir("../..")
	data, err := os.ReadFile(linuxFeasibilityPath)
	if err != nil {
		t.Fatalf("read Linux feasibility manifest: %v", err)
	}
	if err := validateLinuxFeasibilityManifest(data); err != nil {
		t.Fatalf("validate Linux feasibility manifest: %v", err)
	}
	mutations := []struct {
		old string
		new string
	}{
		{`"support": "unsupported"`, `"support": "supported"`},
		{`"platforms": [`, `"platforms": [{"os":"linux","arch":"amd64","support":"supported"},`},
		{`"invariants": [`, `"invariants": [{"id":"CEL-PLAT-INV-002","statement":"Linux constructors may be enabled"},`},
		{`"resources": [`, `"resources": [{"kind":"process","acquisition":"post-start placement","release":"none"},`},
		{"The feasibility slice cannot enable Linux operation constructors or claim qualified attempt persistence", "Linux operation is enabled"},
		{"clone3(CLONE_INTO_CGROUP)", "post-start cgroup placement"},
		{"Root-relative resolution beneath the owned temporary root refuses symbolic links, magic links, parent escapes and absolute-path escapes", "Resolve paths beneath the temporary root"},
		{"A fixture uses private PID, IPC, UTS, mount and network namespaces, a private proc mount, disabled loopback and only descriptors 0, 1 and 2", "A fixture uses isolated namespaces"},
		{"A fixture is an x86-64 static ELF executable with no PT_INTERP and is bound by SHA-256, device and inode", "A fixture has an identity"},
		{"named local ext4 or XFS evidence root", "named local evidence root"},
		{"Fsync the temporary file, publish with renameat2(RENAME_NOREPLACE), fsync the parent directory", "Publish the temporary file"},
		{"A feasible observation records exact Product and probe commits, probe and fixture SHA-256 values", "A feasible observation records the platform"},
		{"Enable Linux operation or claim attempt-persistence qualification", "Enable Linux ARM64"},
	}
	for _, mutation := range mutations {
		changed := bytes.Replace(data, []byte(mutation.old), []byte(mutation.new), 1)
		if bytes.Equal(changed, data) {
			t.Fatalf("mutation source is absent: %q", mutation.old)
		}
		if err := validateLinuxFeasibilityManifest(changed); err == nil {
			t.Fatalf("mutation accepted: %q", mutation.old)
		}
	}
}

func validateLinuxFeasibilityManifest(data []byte) error {
	var manifest linuxFeasibilityManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if manifest.SliceID != "cel-plat-linux-amd64-feas-001" ||
		manifest.Owner != "Linux AMD64 feasibility probe" ||
		!linuxCanonicalStateRetained(manifest.CanonicalState) ||
		!slices.Contains(manifest.NonGoals, "Enable Linux operation or claim attempt-persistence qualification") ||
		!linuxPlatformUnsupported(manifest.Platforms) ||
		!linuxInvariantRetained(manifest.Invariants) ||
		!linuxResourcesRetained(manifest.Resources) {
		return errors.New("Linux feasibility boundary differs from its semantic contract")
	}
	return nil
}

func linuxCanonicalStateRetained(state []string) bool {
	required := []string{
		"Linux operation execution remains unsupported and attempt persistence remains unqualified",
		"Windows AMD64 remains the only qualified operation boundary",
		"Root-relative resolution beneath the owned temporary root refuses symbolic links, magic links, parent escapes and absolute-path escapes",
		"A fixture uses private PID, IPC, UTS, mount and network namespaces, a private proc mount, disabled loopback and only descriptors 0, 1 and 2",
		"A fixture is an x86-64 static ELF executable with no PT_INTERP and is bound by SHA-256, device and inode",
		"A feasible observation records exact Product and probe commits, probe and fixture SHA-256 values, Linux architecture, kernel release, boot ID, cgroup mount and subtree identities, filesystem type and device, namespace configuration and primitive outcomes",
	}
	if len(state) < len(required) {
		return false
	}
	for _, value := range required {
		if !slices.Contains(state, value) {
			return false
		}
	}
	return true
}

func linuxPlatformUnsupported(platforms []linuxPlatform) bool {
	return len(platforms) == 2 && platforms[0] == (linuxPlatform{
		OS: "linux", Arch: "amd64", Support: "unsupported",
	}) && platforms[1] == (linuxPlatform{
		OS: "other", Arch: "other", Support: "unsupported",
	})
}

func linuxInvariantRetained(invariants []linuxInvariant) bool {
	if len(invariants) != 4 {
		return false
	}
	ids := make(map[string]string, len(invariants))
	for _, invariant := range invariants {
		if _, exists := ids[invariant.ID]; exists {
			return false
		}
		ids[invariant.ID] = invariant.Statement
	}
	return strings.Contains(ids["CEL-PLAT-INV-001"], "private PID, IPC, UTS, mount and network namespaces") &&
		strings.Contains(ids["CEL-PLAT-INV-001"], "only descriptors 0, 1 and 2") &&
		strings.Contains(ids["CEL-PLAT-INV-001"], "static x86-64 ELF identity with no PT_INTERP") &&
		strings.Contains(ids["CEL-PLAT-INV-001"], "root-relative resolution refuses links and path escapes") &&
		ids["CEL-PLAT-INV-002"] == "The feasibility slice cannot enable Linux operation constructors or claim qualified attempt persistence" &&
		ids["CEL-PLAT-INV-003"] != "" && ids["CEL-PLAT-INV-004"] != ""
}

func linuxResourcesRetained(resources []linuxResource) bool {
	if len(resources) != 2 {
		return false
	}
	process := slices.ContainsFunc(resources, func(resource linuxResource) bool {
		return resource.Kind == "process" && strings.Contains(resource.Acquisition, "clone3(CLONE_INTO_CGROUP)")
	})
	durable := slices.ContainsFunc(resources, func(resource linuxResource) bool {
		return resource.Kind == "durable" && strings.Contains(resource.Acquisition, "ext4 or XFS") &&
			strings.Contains(resource.Release, "renameat2(RENAME_NOREPLACE)") &&
			strings.Count(strings.ToLower(resource.Release), "fsync") == 2
	})
	return process && durable
}
