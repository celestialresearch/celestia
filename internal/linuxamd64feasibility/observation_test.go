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
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeObservationAcceptsCanonicalFeasibleEvidence(t *testing.T) {
	value := feasibleObservation()
	decoded, err := decodeObservation(marshalObservation(t, value))
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("decoded=%+v error=%v", decoded, err)
	}
}

func TestDecodeObservationRejectsInvalidEnvelope(t *testing.T) {
	valid := marshalObservation(t, feasibleObservation())
	deep := append(bytes.Repeat([]byte("["), 34), '0')
	deep = append(deep, bytes.Repeat([]byte("]"), 34)...)
	manyTokens := append([]byte("["), bytes.Repeat([]byte("0,"), 1025)...)
	manyTokens[len(manyTokens)-1] = ']'
	cases := map[string][]byte{
		"empty":              nil,
		"invalid UTF-8":      append(valid[:10], 0xff),
		"oversized":          bytes.Repeat([]byte("x"), maxObservationBytes+1),
		"leading whitespace": append([]byte(" "), valid...),
		"trailing data":      append(append([]byte{}, valid...), 'x'),
		"unknown field":      append(bytes.TrimSuffix(valid, []byte("}")), []byte(`,"unknown":1}`)...),
		"duplicate field": append(bytes.TrimSuffix(valid, []byte("}")),
			[]byte(`,"status":"feasible"}`)...),
		"duplicate nested field": bytes.Replace(valid,
			[]byte(`"kernel_release":"6.12.0"`),
			[]byte(`"kernel_release":"6.12.0","kernel_release":"6.12.0"`), 1),
		"unknown nested field": bytes.Replace(valid,
			[]byte(`"architecture":"amd64"`),
			[]byte(`"architecture":"amd64","unknown":true`), 1),
		"unpaired surrogate": bytes.Replace(valid,
			[]byte(`"kernel_release":"6.12.0"`),
			[]byte(`"kernel_release":"\ud800"`), 1),
		"noncanonical number": bytes.Replace(valid, []byte(`"device":1`), []byte(`"device":1.0`), 1),
		"scalar":              []byte("1"),
		"unterminated array":  []byte("["),
		"unterminated object": []byte("{"),
		"excessive depth":     deep,
		"token budget":        manyTokens,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeObservation(data); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
}

func TestDecodeObservationRejectsBrokenInvariants(t *testing.T) {
	cases := map[string]func(*observation){
		"identity":          func(value *observation) { value.ProductCommit = "invalid" },
		"nonhex identity":   func(value *observation) { value.ProductCommit = strings.Repeat("g", 40) },
		"uppercase hash":    func(value *observation) { value.ProbeSHA256 = strings.Repeat("A", 64) },
		"empty reason":      func(value *observation) { value.Reason = "" },
		"reason character":  func(value *observation) { value.Reason = "not-valid" },
		"reason length":     func(value *observation) { value.Reason = strings.Repeat("a", 129) },
		"host":              func(value *observation) { value.Host.OperatingSystem = "windows" },
		"host architecture": func(value *observation) { value.Host.Architecture = "arm64" },
		"kernel control":    func(value *observation) { value.Host.KernelRelease = "6.12\n" },
		"boot ID separator": func(value *observation) { value.Host.BootID = strings.Repeat("a", 36) },
		"boot ID character": func(value *observation) { value.Host.BootID = "01234567-89ab-cdef-0123-456789abcdeg" },
		"boot ID length":    func(value *observation) { value.Host.BootID = "short" },
		"status":            func(value *observation) { value.Status = "proposed" },
		"primitive order":   func(value *observation) { value.Primitives[0].ID = "file_fsync" },
		"primitive suffix":  func(value *observation) { value.Primitives[2].Outcome = "not_run" },
		"primitive duplicate": func(value *observation) {
			*value = unavailableObservation()
			value.Primitives[3].Outcome = "unavailable"
		},
		"missing terminal": func(value *observation) {
			*value = unavailableObservation()
			for index := range value.Primitives {
				value.Primitives[index].Outcome = "passed"
			}
		},
		"wrong terminal": func(value *observation) {
			*value = unavailableObservation()
			value.Primitives[2].Outcome = "failed"
		},
		"feasible primitive": func(value *observation) { value.Primitives[0].Outcome = "failed" },
		"namespace":          func(value *observation) { value.Evidence.Namespaces.Descriptors[2] = 3 },
		"identity map":       func(value *observation) { value.Evidence.Namespaces.UIDMap[0].Length = 0 },
		"cgroup":             func(value *observation) { value.Evidence.Cgroup.SubtreeInode = 0 },
		"cgroup mount":       func(value *observation) { value.Evidence.Cgroup.MountDevice = 0 },
		"cgroup device":      func(value *observation) { value.Evidence.Cgroup.SubtreeDevice++ },
		"evidence root":      func(value *observation) { value.Evidence.Evidence.Filesystem = "tmpfs" },
		"evidence device":    func(value *observation) { value.Evidence.Evidence.Device = 0 },
		"fixture":            func(value *observation) { value.Evidence.Fixture.PTInterp = true },
		"fixture type":       func(value *observation) { value.Evidence.Fixture.ELFType = "ET_REL" },
		"cleanup":            func(value *observation) { value.Cleanup.Complete = false },
		"duplicate PID":      func(value *observation) { value.Cleanup.Members[1].PID = value.Cleanup.Members[0].PID },
		"live completed PID": func(value *observation) { value.Cleanup.Members[0].Exited = false },
		"missing evidence":   func(value *observation) { value.Evidence = nil },
		"cancelled cleanup": func(value *observation) {
			*value = cancelledObservation()
			value.Cleanup.Complete = false
		},
		"forbidden evidence": func(value *observation) {
			*value = unavailableObservation()
			value.Evidence.Fixture = feasibleObservation().Evidence.Fixture
		},
		"missing prefix evidence": func(value *observation) {
			*value = unavailableObservation()
			value.Evidence = nil
		},
		"unattempted complete cleanup": func(value *observation) {
			*value = unavailableObservation()
			value.Cleanup.Complete = true
		},
		"unattempted nonempty cleanup": func(value *observation) {
			*value = unavailableObservation()
			value.Cleanup.CgroupEmpty = true
		},
		"unattempted started cleanup": func(value *observation) {
			*value = terminalObservation("indeterminate", "process_state_indeterminate", 3)
		},
		"complete nonempty cleanup": func(value *observation) {
			value.Cleanup.CgroupEmpty = false
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := feasibleObservation()
			mutate(&value)
			if _, err := decodeObservation(marshalObservation(t, value)); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
}

func TestDecodeObservationAcceptsTerminalNonSuccessStates(t *testing.T) {
	cases := []observation{
		unavailableObservation(),
		unavailableAfterCleanupObservation(),
		failedObservation(),
		cancelledObservation(),
		indeterminateObservation(),
	}
	for _, value := range cases {
		t.Run(value.Status, func(t *testing.T) {
			if _, err := decodeObservation(marshalObservation(t, value)); err != nil {
				t.Fatalf("decode: %v", err)
			}
		})
	}
}

func TestDecodeObservationRejectsIncompleteRefusalCleanup(t *testing.T) {
	value := unavailableAfterCleanupObservation()
	value.Cleanup.Complete = false
	if _, err := decodeObservation(marshalObservation(t, value)); err == nil {
		t.Fatal("incomplete refusal cleanup accepted")
	}
}

func TestDecodeObservationPreservesIncompleteCleanupFailure(t *testing.T) {
	value := terminalObservation("failed", "cleanup_failed", primitiveCount-1)
	value.Cleanup = emptyCleanup()
	value.Cleanup.Attempted = true
	value.Cleanup.Members[0] = memberObservation{Role: memberRoles[0], PID: 100}
	value.Cleanup.Members[1] = memberObservation{Role: memberRoles[1], PID: 101, Exited: true}
	value.Cleanup.Members[2] = memberObservation{Role: memberRoles[2], PID: 102, Exited: true}
	if _, err := decodeObservation(marshalObservation(t, value)); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestDecodeObservationRejectsInvalidProcessEvidence(t *testing.T) {
	cases := []observation{feasibleObservation(), feasibleObservation(), feasibleObservation()}
	cases[0].Cleanup.Members[1] = memberObservation{Role: memberRoles[1]}
	cases[1].Cleanup.Members[2] = memberObservation{Role: memberRoles[2]}
	cases[2].Cleanup.Members[3].Exited = true
	for _, value := range cases {
		if _, err := decodeObservation(marshalObservation(t, value)); err == nil {
			t.Fatal("missing process evidence accepted")
		}
	}
	for _, status := range []string{"unavailable", "failed", "cancelled", "indeterminate"} {
		value := terminalObservation(status, status, 0)
		value.Cleanup = feasibleObservation().Cleanup
		if _, err := decodeObservation(marshalObservation(t, value)); err == nil {
			t.Fatalf("%s accepted owned process before clone3", status)
		}
	}
}

func TestDecodeObservationRejectsUnattemptedStartedFailureCleanup(t *testing.T) {
	value := terminalObservation("failed", "process_failed", 3)
	if _, err := decodeObservation(marshalObservation(t, value)); err == nil {
		t.Fatal("unattempted started failure cleanup accepted")
	}
}

func feasibleObservation() observation {
	value := observation{
		SchemaVersion: observationSchema,
		Status:        "feasible",
		Reason:        "all_primitives_passed",
		ProductCommit: strings.Repeat("a", 40),
		ProbeCommit:   strings.Repeat("b", 40),
		ProbeSHA256:   strings.Repeat("c", 64),
		Host: hostObservation{
			OperatingSystem: "linux", Architecture: "amd64", KernelRelease: "6.12.0",
			BootID: "01234567-89ab-cdef-0123-456789abcdef",
		},
		Evidence: &observationEvidence{
			Cgroup:   &cgroupObservation{MountDevice: 1, MountInode: 2, SubtreeDevice: 1, SubtreeInode: 3},
			Evidence: &evidenceRoot{Filesystem: "ext4", Device: 4},
			Namespaces: &namespaceObservation{
				User: true, PID: true, IPC: true, UTS: true, Mount: true, Network: true,
				PrivateProc: true, LoopbackDisabled: true, MountPropagation: "private",
				UIDMap: [1]idMapObservation{{Length: 1}}, GIDMap: [1]idMapObservation{{Length: 1}},
				Descriptors: [3]int{0, 1, 2},
			},
			Fixture: &fixtureObservation{
				SHA256: strings.Repeat("d", 64), ELFMachine: "x86_64", ELFType: "ET_EXEC",
				Device: 5, Inode: 6,
			},
		},
		Cleanup: cleanupObservation{
			Attempted: true, Complete: true, CgroupEmpty: true,
			Members: [memberCount]memberObservation{
				{Role: memberRoles[0], PID: 100, Exited: true},
				{Role: memberRoles[1], PID: 101, Exited: true},
				{Role: memberRoles[2], PID: 102, Exited: true},
				{Role: memberRoles[3]},
			},
		},
	}
	for index := range value.Primitives {
		value.Primitives[index] = primitiveObservation{ID: primitiveIDs[index], Outcome: "passed"}
	}
	return value
}

func unavailableObservation() observation {
	return terminalObservation("unavailable", "clone3_unavailable", 2)
}

func unavailableAfterCleanupObservation() observation {
	value := terminalObservation("unavailable", "fixture_unavailable", 9)
	value.Cleanup = feasibleObservation().Cleanup
	return value
}

func failedObservation() observation {
	value := terminalObservation("failed", "fixture_failed", 9)
	value.Cleanup = feasibleObservation().Cleanup
	return value
}

func cancelledObservation() observation {
	value := terminalObservation("cancelled", "cancelled", 11)
	value.Cleanup = feasibleObservation().Cleanup
	return value
}

func indeterminateObservation() observation {
	return terminalObservation("indeterminate", "host_state_indeterminate", 1)
}

func terminalObservation(status, reason string, terminal int) observation {
	value := feasibleObservation()
	value.Status = status
	value.Reason = reason
	value.Cleanup = emptyCleanup()
	for index := range value.Primitives {
		outcome := "not_run"
		if index < terminal {
			outcome = "passed"
		}
		if index == terminal {
			outcome = status
		}
		value.Primitives[index].Outcome = outcome
	}
	trimTerminalEvidence(&value, terminal)
	return value
}

func trimTerminalEvidence(value *observation, terminal int) {
	if terminal <= 12 {
		value.Evidence.Evidence = nil
	}
	if terminal <= 9 {
		value.Evidence.Fixture = nil
	}
	trimTerminalNamespace(value, terminal)
	if terminal == 0 {
		value.Evidence.Cgroup = nil
	}
	if value.Evidence.Cgroup == nil && value.Evidence.Namespaces == nil &&
		value.Evidence.Fixture == nil && value.Evidence.Evidence == nil {
		value.Evidence = nil
	}
}

func trimTerminalNamespace(value *observation, terminal int) {
	if terminal <= 7 {
		value.Evidence.Namespaces = nil
	} else if terminal == 8 {
		value.Evidence.Namespaces.Descriptors = [3]int{}
	}
}

func emptyCleanup() cleanupObservation {
	var members [memberCount]memberObservation
	for index := range members {
		members[index].Role = memberRoles[index]
	}
	return cleanupObservation{Members: members}
}

func marshalObservation(t *testing.T, value observation) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
