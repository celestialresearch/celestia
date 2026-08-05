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
		"identity":         func(value *observation) { value.ProductCommit = "invalid" },
		"host":             func(value *observation) { value.Host.OperatingSystem = "windows" },
		"status":           func(value *observation) { value.Status = "proposed" },
		"primitive order":  func(value *observation) { value.Primitives[0].ID = "file_fsync" },
		"primitive suffix": func(value *observation) { value.Primitives[2].Outcome = "not_run" },
		"primitive duplicate": func(value *observation) {
			*value = unavailableObservation()
			value.Primitives[3].Outcome = "unavailable"
		},
		"feasible primitive": func(value *observation) { value.Primitives[0].Outcome = "failed" },
		"namespace":          func(value *observation) { value.Evidence.Namespaces.Descriptors[2] = 3 },
		"cgroup":             func(value *observation) { value.Evidence.Cgroup.SubtreeInode = 0 },
		"evidence root":      func(value *observation) { value.Evidence.Evidence.Filesystem = "tmpfs" },
		"fixture":            func(value *observation) { value.Evidence.Fixture.PTInterp = true },
		"cleanup":            func(value *observation) { value.Cleanup.Complete = false },
		"duplicate PID":      func(value *observation) { value.Cleanup.Members[1].PID = value.Cleanup.Members[0].PID },
		"missing evidence":   func(value *observation) { value.Evidence = nil },
		"cancelled cleanup": func(value *observation) {
			*value = cancelledObservation()
			value.Cleanup.Complete = false
		},
		"forbidden evidence": func(value *observation) {
			*value = unavailableObservation()
			value.Evidence = feasibleObservation().Evidence
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
	if _, err := decodeObservation(marshalObservation(t, value)); err != nil {
		t.Fatalf("decode: %v", err)
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
		Evidence: &feasibilityEvidence{
			Cgroup:   cgroupObservation{MountDevice: 1, MountInode: 2, SubtreeDevice: 1, SubtreeInode: 3},
			Evidence: evidenceRoot{Filesystem: "ext4", Device: 4},
			Namespaces: namespaceObservation{
				User: true, PID: true, IPC: true, UTS: true, Mount: true, Network: true,
				PrivateProc: true, LoopbackDisabled: true, MountPropagation: "private",
				UIDMap: [1]idMapObservation{{Length: 1}}, GIDMap: [1]idMapObservation{{Length: 1}},
				Descriptors: [3]int{0, 1, 2},
			},
			Fixture: fixtureObservation{
				SHA256: strings.Repeat("d", 64), ELFMachine: "x86_64", ELFType: "ET_EXEC",
				Device: 5, Inode: 6,
			},
		},
		Cleanup: cleanupObservation{
			Attempted: true, Complete: true, CgroupEmpty: true,
			Members: [memberCount]memberObservation{
				{Role: memberRoles[0], PID: 100, Exited: true},
				{Role: memberRoles[1], PID: 101, Exited: true},
				{Role: memberRoles[2]},
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
	return terminalObservation("failed", "fixture_failed", 9)
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
	value.Evidence = nil
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
	return value
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
