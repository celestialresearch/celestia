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

//go:build linux && amd64

package linuxamd64feasibility

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	nativeFixtureOutputLimit = 1 << 10
	nativeMemoryLimit        = "67108864"
	nativeMemoryRequest      = "134217728"
)

var errNativeFixtureOutput = errors.New("native fixture output exceeds limit")

type nativeFixtureOptions struct {
	mode        string
	value       string
	pidsMax     string
	memoryMax   string
	timeout     bool
	allowStderr bool
}

type nativeFixtureState struct {
	output    string
	success   bool
	timedOut  bool
	oomKilled bool
}

type nativeFixtureOutput struct {
	bytes.Buffer
}

func (output *nativeFixtureOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > nativeFixtureOutputLimit {
		return 0, errNativeFixtureOutput
	}
	return output.Buffer.Write(data)
}

func TestLinuxHostileFixtureNative(t *testing.T) {
	if os.Getenv("CELESTIA_CGROUP_ROOT") == "" || os.Getenv("CELESTIA_HOSTILE_FIXTURE") == "" {
		return
	}
	cases := map[string]struct {
		options nativeFixtureOptions
		output  string
		success bool
	}{
		"network": {
			options: nativeFixtureOptions{mode: "network", value: "127.0.0.1:9"},
			output:  "denied", success: true,
		},
		"host file": {
			options: nativeFixtureOptions{mode: "file", value: "/etc/passwd"},
			output:  "denied", success: true,
		},
		"environment": {
			options: nativeFixtureOptions{mode: "environment"}, output: "denied", success: true,
		},
		"descriptors": {
			options: nativeFixtureOptions{mode: "descriptors"}, output: "denied", success: true,
		},
		"process count": {
			options: nativeFixtureOptions{mode: "descendant", pidsMax: "1"},
			output:  "blocked", success: true,
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			state := runNativeFixture(t, test.options)
			if state.output == "allowed" || state.output != test.output || state.success != test.success {
				t.Fatalf("state = %+v", state)
			}
		})
	}
	t.Run("memory", func(t *testing.T) {
		state := runNativeFixture(t, nativeFixtureOptions{
			mode: "memory", value: nativeMemoryRequest,
			memoryMax: nativeMemoryLimit, allowStderr: true,
		})
		if !state.oomKilled || state.output == "allowed" || state.success {
			t.Fatalf("state = %+v", state)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		state := runNativeFixture(t, nativeFixtureOptions{mode: "hang", timeout: true})
		if !state.timedOut || state.success {
			t.Fatalf("state = %+v", state)
		}
	})
}

func runNativeFixture(t *testing.T, options nativeFixtureOptions) nativeFixtureState {
	t.Helper()
	root := os.Getenv("CELESTIA_CGROUP_ROOT")
	directory, err := openCgroupDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := directory.close(); err != nil {
			t.Errorf("close cgroup root: %v", err)
		}
	}()
	if result := validateDelegatedCgroup(directory); result.Outcome != "passed" {
		t.Fatalf("delegated cgroup = %+v", result)
	}
	fixture := openNativeFixture(t)
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	state := nativeFixtureState{}
	result := useCgroupLeaf(directory, func(leaf ownedCgroupLeaf) cgroupResult {
		return runNativeFixtureLeaf(t.Context(), leaf, fixture, options, &state)
	})
	if result.Outcome != "passed" || !result.CleanupAttempted || !result.CleanupComplete {
		t.Fatalf("result = %+v state = %+v", result, state)
	}
	return state
}

func openNativeFixture(t *testing.T) *os.File {
	t.Helper()
	path := os.Getenv("CELESTIA_HOSTILE_FIXTURE")
	file, _, err := openStaticFixture(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func runNativeFixtureLeaf(
	ctx context.Context,
	leaf ownedCgroupLeaf,
	fixture *os.File,
	options nativeFixtureOptions,
	state *nativeFixtureState,
) (result cgroupResult) {
	if err := leaf.write("pids.max", []byte(clone3TaskLimit)); err != nil {
		return clone3LimitResult(err)
	}
	var output, stderr nativeFixtureOutput
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestClone3BootstrapHelper$", "--",
		clone3BootstrapHelperArgument)
	command.Stdin = strings.NewReader(options.mode + "\n" + options.value)
	command.Stdout = &output
	command.Stderr = &stderr
	child, err := startClone3Child(leaf, command, fixture)
	if child == nil {
		return clone3StartResult(err)
	}
	reaped := false
	defer func() {
		result = cleanupNativeFixture(result, leaf, child, reaped)
	}()
	if err != nil {
		return clone3StartResult(err)
	}
	if prepared := prepareNativeFixture(leaf, child); prepared.Outcome != "passed" {
		return prepared
	}
	if limited := applyNativeFixtureLimits(leaf, options); limited.Outcome != "passed" {
		return limited
	}
	observed, childReaped := observeNativeFixture(child, options, &output, &stderr, state)
	reaped = childReaped
	if options.memoryMax != "" && observed.Outcome == "passed" {
		state.oomKilled, err = nativeMemoryOOMKilled(leaf)
		if err != nil || !state.oomKilled {
			return indeterminateCgroup("fixture_memory_limit_unproven")
		}
	}
	return observed
}

func nativeMemoryOOMKilled(leaf ownedCgroupLeaf) (bool, error) {
	data, err := leaf.read("memory.events", maxCgroupEventsBytes)
	if err != nil {
		return false, err
	}
	return memoryOOMKilled(data)
}

func memoryOOMKilled(data []byte) (bool, error) {
	if len(data) == 0 || len(data) > maxCgroupEventsBytes || data[len(data)-1] != '\n' {
		return false, errCgroupEventsMalformed
	}
	found, killed := false, false
	fieldsSeen := make(map[string]bool)
	for line := range strings.SplitSeq(string(data[:len(data)-1]), "\n") {
		name, value, err := parseMemoryEvent(line, fieldsSeen)
		if err != nil {
			return false, errCgroupEventsMalformed
		}
		if name == "oom_kill" {
			found, killed = true, value > 0
		}
	}
	if !found {
		return false, errCgroupEventsMalformed
	}
	return killed, nil
}

func parseMemoryEvent(line string, fieldsSeen map[string]bool) (string, uint64, error) {
	name, valueText, ok := strings.Cut(line, " ")
	if !ok || !validCgroupName(name) || fieldsSeen[name] || valueText == "" ||
		strings.Contains(valueText, " ") || (len(valueText) > 1 && valueText[0] == '0') {
		return "", 0, errCgroupEventsMalformed
	}
	value, err := strconv.ParseUint(valueText, 10, 64)
	if err != nil {
		return "", 0, errCgroupEventsMalformed
	}
	fieldsSeen[name] = true
	return name, value, nil
}

func TestMemoryOOMKillEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		data   string
		killed bool
		valid  bool
	}{
		{data: "low 0\noom 1\noom_kill 1\n", killed: true, valid: true},
		{data: "low 0\noom 0\noom_kill 0\n", valid: true},
		{data: "low 0\noom 1\n"},
		{data: "oom_kill invalid\n"},
		{data: "oom_kill 1 unexpected\n"},
		{data: "oom_kill 1\nbroken\n"},
		{data: "oom_kill 1\noom_kill 0\n"},
		{data: "oom_kill 01\n"},
		{data: "oom_kill\t1\n"},
		{data: "oom_kill 1"},
	}
	for _, test := range tests {
		killed, err := memoryOOMKilled([]byte(test.data))
		if killed != test.killed || (err == nil) != test.valid {
			t.Fatalf("data=%q killed=%t error=%v", test.data, killed, err)
		}
	}
}

func prepareNativeFixture(leaf ownedCgroupLeaf, child *clone3Child) cgroupResult {
	if child.pidfd < 0 {
		return unavailableCgroup("clone3_pidfd_unavailable")
	}
	if err := verifyClone3Membership(leaf, child.command.Process.Pid); err != nil {
		return clone3MembershipResult(err)
	}
	setupDeadline := time.Now().Add(clone3ProbeTimeout)
	if err := leaf.freeze(setupDeadline); err != nil {
		return clone3FreezeResult(err)
	}
	if err := child.pipes.readyEmpty(); err != nil {
		return indeterminateCgroup("clone3_payload_before_freeze")
	}
	if err := child.pipes.release(); err != nil {
		return indeterminateCgroup("clone3_gate_release_failed")
	}
	if err := child.pipes.readyEmpty(); err != nil {
		return indeterminateCgroup("clone3_payload_before_thaw")
	}
	if err := leaf.thaw(setupDeadline); err != nil {
		return clone3FreezeResult(err)
	}
	if err := child.pipes.waitReady(setupDeadline); err != nil {
		return clone3ReadyResult(err)
	}
	return passedCgroup()
}

func observeNativeFixture(
	child *clone3Child,
	options nativeFixtureOptions,
	output, stderr *nativeFixtureOutput,
	state *nativeFixtureState,
) (cgroupResult, bool) {
	if err := child.pipes.release(); err != nil {
		return indeterminateCgroup("fixture_gate_release_failed"), false
	}
	executionDeadline := time.Now().Add(clone3ProbeTimeout)
	if options.timeout {
		if child.reap(executionDeadline) {
			return indeterminateCgroup("fixture_timeout_not_enforced"), true
		}
		state.timedOut = !time.Now().Before(executionDeadline)
		if !state.timedOut {
			return indeterminateCgroup("fixture_wait_indeterminate"), false
		}
		return cgroupResult{Outcome: "passed", Reason: "fixture_timeout_enforced"}, false
	}
	if !child.reap(executionDeadline) {
		return unavailableCgroup("fixture_exit_timeout"), false
	}
	state.output = output.String()
	state.success = child.command.ProcessState != nil && child.command.ProcessState.Success()
	if stderr.Len() != 0 && !options.allowStderr {
		return indeterminateCgroup("fixture_stderr_nonempty"), true
	}
	return cgroupResult{Outcome: "passed", Reason: "fixture_completed"}, true
}

func applyNativeFixtureLimits(leaf ownedCgroupLeaf, options nativeFixtureOptions) cgroupResult {
	if options.pidsMax != "" {
		if err := leaf.write("pids.max", []byte(options.pidsMax)); err != nil {
			return clone3LimitResult(err)
		}
	}
	if options.memoryMax != "" {
		if err := leaf.write("memory.max", []byte(options.memoryMax)); err != nil {
			return cgroupWriteResult(err)
		}
		if err := leaf.write("memory.swap.max", []byte("0")); err != nil {
			return cgroupWriteResult(err)
		}
	}
	return passedCgroup()
}

func cleanupNativeFixture(
	result cgroupResult,
	leaf ownedCgroupLeaf,
	child *clone3Child,
	reaped bool,
) cgroupResult {
	complete := leaf.write("cgroup.kill", []byte("1")) == nil
	deadline := time.Now().Add(clone3ProbeTimeout)
	if !reaped && !child.reap(deadline) {
		complete = false
	}
	if err := leaf.waitEmpty(deadline); err != nil {
		complete = false
	}
	if err := child.close(); err != nil {
		complete = false
	}
	result.CleanupAttempted = true
	result.CleanupComplete = complete
	return result
}
