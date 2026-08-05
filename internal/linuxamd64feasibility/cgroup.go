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
)

const maxCgroupEventsBytes = 4 << 10

var (
	errCgroupEventsMalformed = errors.New("malformed cgroup events")
	errCgroupEventsOversized = errors.New("oversized cgroup events")
)

type cgroupResult struct {
	Outcome string
	Reason  string
}

func unavailableCgroup(reason string) cgroupResult {
	return cgroupResult{Outcome: "unavailable", Reason: reason}
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
	populated, found := false, false
	for line := range strings.SplitSeq(string(data[:len(data)-1]), "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok || !validCgroupName(name) || (value != "0" && value != "1") || fields[name] {
			return false, errCgroupEventsMalformed
		}
		fields[name] = true
		if name == "populated" {
			populated, found = value == "1", true
		}
	}
	if !found {
		return false, errCgroupEventsMalformed
	}
	return populated, nil
}
