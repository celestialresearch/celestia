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
	"strconv"
	"strings"
)

const maxCgroupEventsBytes = 4 << 10

var (
	errCgroupEventsMalformed = errors.New("malformed cgroup events")
	errCgroupEventsOversized = errors.New("oversized cgroup events")
)

type cgroupResult struct {
	Outcome          string
	Reason           string
	CleanupAttempted bool
	CleanupComplete  bool
	cause            error
}

func unavailableCgroup(reason string) cgroupResult {
	return cgroupResult{Outcome: "unavailable", Reason: reason}
}

func finishCgroupCleanup(result cgroupResult, cleanupError error) cgroupResult {
	if !result.CleanupAttempted {
		result.CleanupAttempted = true
		result.CleanupComplete = cleanupError == nil
	} else if cleanupError != nil {
		result.CleanupComplete = false
	}
	return result
}

func requiredDelegatedControllers(data []byte) bool {
	controllers, ok := cgroupControllers(data)
	return ok && controllers["cpu"] && controllers["memory"] && controllers["pids"]
}

func cgroupControllers(data []byte) (map[string]bool, bool) {
	if len(data) == 0 || len(data) > maxCgroupBytes {
		return nil, false
	}
	controllers := make(map[string]bool)
	for name := range strings.FieldsSeq(string(data)) {
		if !validCgroupName(name) {
			return nil, false
		}
		controllers[name] = true
	}
	return controllers, true
}

func validCgroupName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}

func cgroupPopulated(data []byte) (bool, error) {
	return cgroupEventValue(data, "populated")
}

func cgroupFrozen(data []byte) (bool, error) {
	return cgroupEventValue(data, "frozen")
}

func cgroupEventValue(data []byte, target string) (bool, error) {
	if len(data) == 0 {
		return false, errCgroupEventsMalformed
	}
	if len(data) > maxCgroupEventsBytes {
		return false, errCgroupEventsOversized
	}
	if data[len(data)-1] != '\n' {
		return false, errCgroupEventsMalformed
	}
	fields := make(map[string]bool)
	value, found := false, false
	for line := range strings.SplitSeq(string(data[:len(data)-1]), "\n") {
		name, state, ok := strings.Cut(line, " ")
		if !ok || !validCgroupName(name) || (state != "0" && state != "1") || fields[name] {
			return false, errCgroupEventsMalformed
		}
		fields[name] = true
		if name == target {
			value, found = state == "1", true
		}
	}
	if !found {
		return false, errCgroupEventsMalformed
	}
	return value, nil
}

func cgroupContainsPID(data []byte, target int) (bool, error) {
	if target <= 0 || len(data) == 0 || len(data) > maxCgroupEventsBytes ||
		data[len(data)-1] != '\n' {
		return false, errCgroupEventsMalformed
	}
	found := false
	for value := range strings.SplitSeq(string(data[:len(data)-1]), "\n") {
		if value == "" || (len(value) > 1 && value[0] == '0') {
			return false, errCgroupEventsMalformed
		}
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 0 {
			return false, errCgroupEventsMalformed
		}
		if pid == target {
			found = true
		}
	}
	return found, nil
}
