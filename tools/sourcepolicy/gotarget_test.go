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
	"go/build"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestPolicyTargetCount(t *testing.T) {
	targets := policyTargets()
	cgoTargets := 0
	if build.Default.CgoEnabled {
		cgoTargets = 1
	}
	expected := len(policyBuildTargets) + cgoTargets + len(policyRaceTargets)
	if len(targets) != expected {
		t.Fatalf("targets = %d, want %d", len(targets), expected)
	}
}

func TestPolicyTargetsCoverDefault(t *testing.T) {
	targets := policyTargets()
	for _, policyTarget := range policyBuildTargets {
		foundDefault := slices.ContainsFunc(targets, func(target buildTarget) bool {
			return target.goos == policyTarget.goos &&
				target.goarch == policyTarget.goarch &&
				!target.cgo && !target.race
		})
		if !foundDefault {
			t.Fatalf(
				"missing target %s/%s",
				policyTarget.goos,
				policyTarget.goarch,
			)
		}
	}
}

func TestPolicyTargetsCoverCGO(t *testing.T) {
	targets := policyTargets()
	for _, policyTarget := range policyBuildTargets {
		wantCGO := build.Default.CgoEnabled &&
			policyTarget.goos == runtime.GOOS &&
			policyTarget.goarch == runtime.GOARCH
		foundCGO := slices.ContainsFunc(targets, func(target buildTarget) bool {
			return target.goos == policyTarget.goos &&
				target.goarch == policyTarget.goarch &&
				target.cgo && !target.race
		})
		if foundCGO != wantCGO {
			t.Fatalf(
				"CGO target %s/%s = %t, want %t",
				policyTarget.goos,
				policyTarget.goarch,
				foundCGO,
				wantCGO,
			)
		}
	}
}

func TestPolicyTargetsCoverRace(t *testing.T) {
	targets := policyTargets()
	for _, policyTarget := range policyBuildTargets {
		key := policyTarget.goos + "/" + policyTarget.goarch
		foundRace := slices.ContainsFunc(targets, func(target buildTarget) bool {
			return target.goos == policyTarget.goos &&
				target.goarch == policyTarget.goarch &&
				!target.cgo && target.race
		})
		if foundRace != policyRaceTargets[key] {
			t.Fatalf("race target %s = %t, want %t", key, foundRace, policyRaceTargets[key])
		}
	}
}

func TestGoRaceSkip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "race_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		path: "//go:build race\n\npackage fixture\n\nimport \"testing\"\n\n" +
			"func TestRace(t *testing.T) { t.Skip(\"hidden\") }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{"race_test.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH, cgo: true, race: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want race skip", findings)
	}
}
