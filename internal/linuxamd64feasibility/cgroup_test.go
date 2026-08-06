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
	"errors"
	"strings"
	"testing"
)

func TestCgroupControllersRequireDelegation(t *testing.T) {
	cases := map[string]struct {
		input string
		valid bool
	}{
		"delegated":          {input: "cpu memory pids\n", valid: true},
		"missing controller": {input: "cpu memory\n"},
		"invalid character":  {input: "cpu memory pids=1\n"},
		"empty":              {},
		"oversized":          {input: strings.Repeat("a", maxCgroupBytes+1)},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if actual := requiredDelegatedControllers([]byte(test.input)); actual != test.valid {
				t.Fatalf("actual=%t valid=%t", actual, test.valid)
			}
		})
	}
}

func TestCgroupEventsRequireOneCanonicalPopulation(t *testing.T) {
	cases := map[string]struct {
		input     string
		populated bool
		err       error
	}{
		"empty input":           {err: errCgroupEventsMalformed},
		"missing newline":       {input: "populated 0", err: errCgroupEventsMalformed},
		"missing population":    {input: "frozen 0\n", err: errCgroupEventsMalformed},
		"duplicate population":  {input: "populated 0\npopulated 1\n", err: errCgroupEventsMalformed},
		"invalid value":         {input: "populated 2\n", err: errCgroupEventsMalformed},
		"invalid delimiter":     {input: "populated  0\n", err: errCgroupEventsMalformed},
		"control character":     {input: "populated\t0\n", err: errCgroupEventsMalformed},
		"oversized":             {input: strings.Repeat("a", maxCgroupEventsBytes+1), err: errCgroupEventsOversized},
		"empty cgroup":          {input: "populated 0\nfrozen 0\n"},
		"populated":             {input: "populated 1\nfrozen 0\n", populated: true},
		"future binary counter": {input: "populated 0\nfuture_state 1\n"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			populated, err := cgroupPopulated([]byte(test.input))
			if !errors.Is(err, test.err) || populated != test.populated {
				t.Fatalf("populated=%t err=%v", populated, err)
			}
		})
	}
}

func TestCgroupCleanupPreservesPrimitiveOutcome(t *testing.T) {
	primary := unavailableCgroup("first_refusal")
	complete := finishCgroupCleanup(primary, nil)
	if complete.Outcome != primary.Outcome || complete.Reason != primary.Reason ||
		!complete.CleanupAttempted || !complete.CleanupComplete {
		t.Fatalf("complete=%+v", complete)
	}
	failed := finishCgroupCleanup(primary, errCgroupEventsMalformed)
	if failed.Outcome != primary.Outcome || failed.Reason != primary.Reason ||
		!failed.CleanupAttempted || failed.CleanupComplete {
		t.Fatalf("failed=%+v", failed)
	}
}

func TestCgroupEventsRequireFrozenState(t *testing.T) {
	cases := map[string]struct {
		input  string
		frozen bool
		err    error
	}{
		"frozen":           {input: "populated 1\nfrozen 1\n", frozen: true},
		"not frozen":       {input: "populated 1\nfrozen 0\n"},
		"missing frozen":   {input: "populated 1\n", err: errCgroupEventsMalformed},
		"duplicate frozen": {input: "frozen 0\nfrozen 1\n", err: errCgroupEventsMalformed},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			frozen, err := cgroupFrozen([]byte(test.input))
			if !errors.Is(err, test.err) || frozen != test.frozen {
				t.Fatalf("frozen=%t err=%v", frozen, err)
			}
		})
	}
}

func TestCgroupProcessesRequireCanonicalPIDs(t *testing.T) {
	cases := map[string]struct {
		input string
		found bool
		err   error
	}{
		"present":             {input: "101\n102\n", found: true},
		"absent":              {input: "101\n102\n"},
		"missing newline":     {input: "102", err: errCgroupEventsMalformed},
		"zero":                {input: "0\n", err: errCgroupEventsMalformed},
		"leading zero":        {input: "0102\n", err: errCgroupEventsMalformed},
		"non numeric":         {input: "one\n", err: errCgroupEventsMalformed},
		"empty":               {err: errCgroupEventsMalformed},
		"non-positive target": {input: "102\n", err: errCgroupEventsMalformed},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			target := 102
			if name == "absent" {
				target = 103
			}
			if name == "non-positive target" {
				target = 0
			}
			found, err := cgroupContainsPID([]byte(test.input), target)
			if !errors.Is(err, test.err) || found != test.found {
				t.Fatalf("found=%t err=%v", found, err)
			}
		})
	}
}
