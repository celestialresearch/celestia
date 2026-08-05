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
	"encoding/hex"
	"strings"
	"unicode"
)

var primitiveIDs = [primitiveCount]string{
	"cgroup_v2",
	"delegated_controls",
	"clone3_into_cgroup",
	"user_mapping",
	"private_namespaces",
	"private_proc",
	"mount_propagation",
	"loopback_disabled",
	"descriptor_allowlist",
	"fixture_identity",
	"root_resolution",
	"process_accounting",
	"file_fsync",
	"renameat2_noreplace",
	"directory_fsync",
	"cleanup",
}

var memberRoles = [memberCount]string{
	"bootstrap_or_fixture",
	"descendant",
	"challenge_helper",
	"remaining_owned_slot",
}

func validObservation(value observation) bool {
	return value.SchemaVersion == observationSchema &&
		validObservationStatus(value.Status) &&
		validObservationReason(value.Reason) &&
		validCommit(value.ProductCommit) &&
		validCommit(value.ProbeCommit) &&
		validHash(value.ProbeSHA256) &&
		validHost(value.Host) &&
		validPrimitives(value.Primitives, value.Status) &&
		validObservationEvidence(value.Evidence, value.Primitives) &&
		validCleanup(value.Cleanup) &&
		validProcessEvidence(value.Cleanup, value.Primitives) &&
		validObservationStatusInvariants(value)
}

func validProcessEvidence(
	cleanup cleanupObservation,
	primitives [primitiveCount]primitiveObservation,
) bool {
	owned := false
	for _, member := range cleanup.Members {
		owned = owned || member.PID != 0
	}
	clonePrefix := primitives[0].Outcome == "passed" &&
		primitives[1].Outcome == "passed" && primitives[2].Outcome == "passed"
	if owned && !clonePrefix {
		return false
	}
	return primitives[11].Outcome != "passed" || (cleanup.Members[0].PID != 0 &&
		cleanup.Members[1].PID != 0 && cleanup.Members[2].PID != 0)
}

func validObservationStatus(value string) bool {
	switch value {
	case "feasible", "unavailable", "failed", "cancelled", "indeterminate":
		return true
	default:
		return false
	}
}

func validObservationReason(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validCommit(value string) bool {
	return len(value) == 40 && validLowerHex(value)
}

func validHash(value string) bool {
	return len(value) == 64 && validLowerHex(value)
}

func validLowerHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func validHost(value hostObservation) bool {
	return value.OperatingSystem == "linux" && value.Architecture == "amd64" &&
		validHostText(value.KernelRelease, 256) && validBootID(value.BootID)
}

func validHostText(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit &&
		strings.IndexFunc(value, func(character rune) bool {
			return character > unicode.MaxASCII || unicode.IsControl(character)
		}) < 0
}

func validBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validPrimitives(values [primitiveCount]primitiveObservation, status string) bool {
	terminal := primitiveTerminal(status)
	if terminal == "passed" {
		for index, value := range values {
			if value.ID != primitiveIDs[index] || value.Outcome != terminal {
				return false
			}
		}
		return true
	}
	return validRefusedPrimitives(values, terminal)
}

func primitiveTerminal(status string) string {
	switch status {
	case "feasible":
		return "passed"
	default:
		return status
	}
}

func validRefusedPrimitives(values [primitiveCount]primitiveObservation, terminal string) bool {
	seenTerminal := false
	for index, value := range values {
		if value.ID != primitiveIDs[index] {
			return false
		}
		if !seenTerminal && value.Outcome == "passed" {
			continue
		}
		if !seenTerminal && value.Outcome == terminal {
			seenTerminal = true
			continue
		}
		if seenTerminal && value.Outcome == "not_run" {
			continue
		}
		return false
	}
	return seenTerminal
}

func validCleanup(value cleanupObservation) bool {
	seen := make(map[uint32]struct{})
	for index, member := range value.Members {
		if member.Role != memberRoles[index] || !validMember(member, value.Complete, seen) {
			return false
		}
	}
	if !value.Attempted {
		return !value.Complete && !value.CgroupEmpty && len(seen) == 0
	}
	return !value.Complete || value.CgroupEmpty
}

func validMember(value memberObservation, complete bool, seen map[uint32]struct{}) bool {
	if value.PID == 0 {
		return !value.Exited
	}
	if complete && !value.Exited {
		return false
	}
	if _, duplicate := seen[value.PID]; duplicate {
		return false
	}
	seen[value.PID] = struct{}{}
	return true
}

func validObservationStatusInvariants(value observation) bool {
	switch value.Status {
	case "feasible":
		return value.Reason == "all_primitives_passed" &&
			completeCleanup(value.Cleanup)
	case "cancelled":
		return value.Reason == "cancelled" &&
			completeCleanup(value.Cleanup)
	case "failed":
		return value.Primitives[2].Outcome != "passed" || value.Cleanup.Attempted
	case "unavailable", "indeterminate":
		return value.Reason != "all_primitives_passed" &&
			validRefusalCleanup(value.Cleanup, value.Primitives[2].Outcome == "passed")
	default:
		return false
	}
}

func validRefusalCleanup(value cleanupObservation, childStarted bool) bool {
	return (!childStarted && !value.Attempted) || completeCleanup(value)
}

func validObservationEvidence(
	value *observationEvidence,
	primitives [primitiveCount]primitiveObservation,
) bool {
	cgroupPassed := primitives[0].Outcome == "passed"
	namespacesPassed := primitives[7].Outcome == "passed"
	descriptorsPassed := primitives[8].Outcome == "passed"
	fixturePassed := primitives[9].Outcome == "passed"
	evidenceRootPassed := primitives[12].Outcome == "passed"
	if value == nil {
		return !cgroupPassed && !namespacesPassed && !fixturePassed && !evidenceRootPassed
	}
	return validOptionalCgroup(value.Cgroup, cgroupPassed) &&
		validOptionalNamespaces(value.Namespaces, namespacesPassed, descriptorsPassed) &&
		validOptionalFixture(value.Fixture, fixturePassed) &&
		validOptionalEvidenceRoot(value.Evidence, evidenceRootPassed)
}

func validOptionalCgroup(value *cgroupObservation, required bool) bool {
	if required {
		return value != nil && validCgroup(*value)
	}
	return value == nil
}

func validOptionalEvidenceRoot(value *evidenceRoot, required bool) bool {
	if required {
		return value != nil && validEvidenceRoot(*value)
	}
	return value == nil
}

func validOptionalNamespaces(value *namespaceObservation, required, descriptorsPassed bool) bool {
	if required {
		return value != nil && validNamespaces(*value, descriptorsPassed)
	}
	return value == nil
}

func validOptionalFixture(value *fixtureObservation, required bool) bool {
	if required {
		return value != nil && validFixture(*value)
	}
	return value == nil
}

func validCgroup(value cgroupObservation) bool {
	return value.MountDevice != 0 && value.MountInode != 0 &&
		value.SubtreeDevice == value.MountDevice && value.SubtreeInode != 0
}

func validEvidenceRoot(value evidenceRoot) bool {
	return (value.Filesystem == "ext4" || value.Filesystem == "xfs") && value.Device != 0
}

func validNamespaces(value namespaceObservation, descriptorsPassed bool) bool {
	wantDescriptors := [3]int{}
	if descriptorsPassed {
		wantDescriptors = [3]int{0, 1, 2}
	}
	return validNamespaceSet(value) && value.PrivateProc && value.LoopbackDisabled &&
		value.MountPropagation == "private" && validIDMap(value.UIDMap) &&
		validIDMap(value.GIDMap) && value.Descriptors == wantDescriptors
}

func validNamespaceSet(value namespaceObservation) bool {
	return value.User && value.PID && value.IPC && value.UTS && value.Mount && value.Network
}

func validIDMap(values [1]idMapObservation) bool {
	return values[0].Length != 0
}

func validFixture(value fixtureObservation) bool {
	return validHash(value.SHA256) && value.ELFMachine == "x86_64" &&
		(value.ELFType == "ET_EXEC" || value.ELFType == "ET_DYN") && !value.PTInterp &&
		value.Device != 0 && value.Inode != 0
}

func completeCleanup(value cleanupObservation) bool {
	return value.Attempted && value.Complete && value.CgroupEmpty &&
		value.Members[0].PID != 0
}
