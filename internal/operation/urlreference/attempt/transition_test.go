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

//go:build windows

package attemptstore

import (
	"errors"
	"testing"
)

func TestObservationRejectsUnknownStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	tests := []struct {
		name   string
		change func(*Observation)
	}{
		{
			name: "process",
			change: func(observation *Observation) {
				observation.ProcessStatus = "unknown"
			},
		},
		{
			name: "protocol",
			change: func(observation *Observation) {
				observation.ProtocolStatus = "unknown"
			},
		},
		{
			name: "duration",
			change: func(observation *Observation) {
				observation.DurationNS = -1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := testObservationFor(t, accepted)
			test.change(&observation)
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid observation accepted: %v", err)
			}
		})
	}
}

func TestObservationRejectsContradictoryTerminal(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := testObservationFor(t, accepted)
	observation.ProcessStatus = "exit_failed"
	observation.ProtocolStatus = "not_run"
	observation.VerificationID = ""
	observation.VerificationVer = ""
	observation.ExpectedOutput = ""
	observation.VerificationPass = false
	if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("contradictory verified observation accepted: %v", err)
	}
}

func TestObservationRejectsInvalidTerminalTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := testObservationFor(t, accepted)
	for _, terminal := range []string{"unknown", "cancelled", "timed_out"} {
		t.Run(terminal, func(t *testing.T) {
			observation := base
			observation.TerminalStatus = terminal
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid terminal transition accepted: %v", err)
			}
		})
	}
}

func TestObservationRejectsTimeoutWithoutProcessError(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := observationWithoutVerification(
		testObservationFor(t, accepted),
	)
	observation.ProcessStatus = "timed_out"
	observation.ProcessError = ""
	observation.ProtocolStatus = "not_run"
	observation.TerminalStatus = "timed_out"
	if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("timeout without process error accepted: %v", err)
	}
}

func TestObservationAcceptsContractTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	verified := testObservationFor(t, accepted)
	unverified := verified
	unverified.TerminalStatus = "executed_unverified"
	unverified.VerificationPass = false
	failedResponse := observationWithoutVerification(verified)
	failedResponse.TerminalStatus = "failed"
	failedResponse.ExitCode = 2
	workerFailed := failedResponse
	workerFailed.ProcessStatus = "exit_failed"
	workerFailed.ProcessError = "worker status failed"
	workerFailed.ExitCode = 3
	failedProcess := failedResponse
	failedProcess.ProcessStatus = "exit_failed"
	failedProcess.ProtocolStatus = "not_run"
	failedProcess.ProcessError = "worker failed"
	failedProcess.ExitCode = 0
	cancelled := failedProcess
	cancelled.ProcessStatus = "cancelled"
	cancelled.TerminalStatus = "cancelled"
	timedOut := failedProcess
	timedOut.ProcessStatus = "timed_out"
	timedOut.TerminalStatus = "timed_out"
	deadlineCancelled := timedOut
	deadlineCancelled.ProcessStatus = "cancelled"
	for _, observation := range []Observation{
		verified,
		unverified,
		failedResponse,
		workerFailed,
		failedProcess,
		cancelled,
		timedOut,
		deadlineCancelled,
	} {
		if err := validateObservation(observation); err != nil {
			t.Fatalf("valid transition rejected: %+v: %v", observation, err)
		}
	}
}

func TestObservationAcceptsAndRejectsCleanupFailureTransitions(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.TerminalStatus = "failed"
	validCleanupFailure := base
	validCleanupFailure.ProcessStatus = "cleanup_failed"
	validCleanupFailure.ProcessError = "cleanup failed"
	validCleanupFailure.CleanupComplete = false
	validCleanupFailure.ProtocolStatus = "not_run"
	if err := validateObservation(validCleanupFailure); err != nil {
		t.Fatalf("valid cleanup failure rejected: %v", err)
	}
	invalidCleanupFailure := validCleanupFailure
	invalidCleanupFailure.CleanupComplete = true
	if err := validateObservation(invalidCleanupFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cleanup failure with complete cleanup accepted: %v", err)
	}
	protocolCleanupFailure := invalidCleanupFailure
	protocolCleanupFailure.ProtocolStatus = "valid"
	if err := validateObservation(protocolCleanupFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cleanup failure with protocol result accepted: %v", err)
	}
	missingProcessError := invalidCleanupFailure
	missingProcessError.ProcessError = ""
	if err := validateObservation(missingProcessError); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cleanup failure without process error accepted: %v", err)
	}
	validProcessFailure := base
	validProcessFailure.ProcessStatus = "output_overflow"
	validProcessFailure.ProcessError = "output limit"
	validProcessFailure.CleanupComplete = true
	validProcessFailure.ProtocolStatus = "not_run"
	if err := validateObservation(validProcessFailure); err != nil {
		t.Fatalf("valid output failure rejected: %v", err)
	}
	validStartFailure := validProcessFailure
	validStartFailure.ProcessStatus = "start_failed"
	validStartFailure.ProcessError = "start failed"
	validStartFailure.Stdout = nil
	validStartFailure.Stderr = nil
	if err := validateObservation(validStartFailure); err != nil {
		t.Fatalf("valid start failure rejected: %v", err)
	}
	invalidCompletedFailure := validProcessFailure
	invalidCompletedFailure.ProcessStatus = "completed"
	invalidCompletedFailure.ProcessError = "unexpected process error"
	if err := validateObservation(invalidCompletedFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("completed failure with process error accepted: %v", err)
	}
	invalidProcessFailure := validProcessFailure
	invalidProcessFailure.ProcessStatus = "cancelled"
	if err := validateObservation(invalidProcessFailure); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cancelled failed observation accepted: %v", err)
	}
}

func TestObservationPreservesPrimaryOutcomeDuringCleanupFailure(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.ProcessError = "primary and cleanup failure"
	base.ProtocolStatus = "not_run"
	base.CleanupComplete = false
	tests := []struct {
		process  string
		terminal string
	}{
		{process: "timed_out", terminal: "timed_out"},
		{process: "cancelled", terminal: "cancelled"},
		{process: "exit_failed", terminal: "failed"},
		{process: "completed", terminal: "failed"},
		{process: "output_overflow", terminal: "failed"},
		{process: "error_overflow", terminal: "failed"},
		{process: "cleanup_failed", terminal: "failed"},
		{process: "start_failed", terminal: "failed"},
	}
	for _, test := range tests {
		observation := base
		observation.ProcessStatus = test.process
		observation.TerminalStatus = test.terminal
		if test.process == "start_failed" {
			observation.Stdout = nil
			observation.Stderr = nil
		}
		if err := validateObservation(observation); err != nil {
			t.Fatalf("%s with cleanup failure rejected: %v", test.process, err)
		}
	}
}

func TestObservationRejectsInvalidCleanupImpairedStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.ProcessStatus = "start_failed"
	base.ProcessError = "start and cleanup failed"
	base.ProtocolStatus = "not_run"
	base.CleanupComplete = false
	base.TerminalStatus = "failed"
	tests := []struct {
		name   string
		mutate func(*Observation)
	}{
		{
			name: "start exit code",
			mutate: func(observation *Observation) {
				observation.ExitCode = 1
			},
		},
		{
			name: "start output",
			mutate: func(observation *Observation) {
				observation.Stdout = []byte("unexpected")
			},
		},
		{
			name: "unknown process",
			mutate: func(observation *Observation) {
				observation.ProcessStatus = "unknown"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			test.mutate(&observation)
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid cleanup-impaired state accepted: %+v", observation)
			}
		})
	}
}

func TestObservationRejectsStartFailureStreams(t *testing.T) {
	accepted, _ := testAccepted(t)
	observation := observationWithoutVerification(testObservationFor(t, accepted))
	observation.ProcessStatus = "start_failed"
	observation.ProcessError = "start failed"
	observation.ExitCode = 0
	observation.ProtocolStatus = "not_run"
	observation.Stdout = []byte("worker did not start")
	for _, terminal := range []string{"failed", "timed_out"} {
		observation.TerminalStatus = terminal
		if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s start failure streams accepted: %+v", terminal, observation)
		}
	}
}

func TestObservationRejectsContradictoryProcessProtocolStates(t *testing.T) {
	accepted, _ := testAccepted(t)
	base := observationWithoutVerification(testObservationFor(t, accepted))
	base.TerminalStatus = "failed"
	base.ProcessError = "worker failed"
	base.CleanupComplete = true
	tests := []struct {
		name     string
		process  string
		protocol string
		exitCode uint32
	}{
		{name: "start valid", process: "start_failed", protocol: "valid"},
		{name: "start rejected", process: "start_failed", protocol: "rejected"},
		{name: "start exit", process: "start_failed", protocol: "not_run", exitCode: 1},
		{name: "output valid", process: "output_overflow", protocol: "valid", exitCode: 1},
		{name: "output rejected", process: "output_overflow", protocol: "rejected", exitCode: 1},
		{name: "error valid", process: "error_overflow", protocol: "valid", exitCode: 1},
		{name: "exit valid", process: "exit_failed", protocol: "valid", exitCode: 1},
		{name: "exit rejected code", process: "exit_failed", protocol: "valid", exitCode: 2},
		{name: "cancelled failed", process: "cancelled", protocol: "not_run", exitCode: 1},
		{name: "timed out failed", process: "timed_out", protocol: "not_run", exitCode: 1},
		{name: "completed not run", process: "completed", protocol: "not_run"},
		{name: "completed valid zero", process: "completed", protocol: "valid"},
		{name: "completed valid failure", process: "completed", protocol: "valid", exitCode: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			observation.ProcessStatus = test.process
			observation.ProtocolStatus = test.protocol
			observation.ExitCode = test.exitCode
			if test.process == "completed" {
				observation.ProcessError = ""
			}
			if err := validateObservation(observation); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("contradictory observation accepted: %+v", observation)
			}
		})
	}
}

func observationWithoutVerification(observation Observation) Observation {
	observation.VerificationID = ""
	observation.VerificationVer = ""
	observation.ExpectedOutput = ""
	observation.VerificationPass = false
	return observation
}

func TestFailureTransitionHelpers(t *testing.T) {
	base := Observation{
		ProcessStatus:  "completed",
		ProcessError:   "error",
		ProtocolStatus: "not_run",
		TerminalStatus: "failed",
	}
	withVerification := base
	withVerification.VerificationID = "unexpected"
	if validFailedObservation(withVerification) {
		t.Fatal("failed observation retained verification")
	}
	if validCleanupImpairedFailure(Observation{}) {
		t.Fatal("cleanup-impaired failure without process error accepted")
	}
	if validCleanupImpairedFailure(Observation{
		ProcessStatus:  "completed",
		ProcessError:   "error",
		ProtocolStatus: "valid",
	}) {
		t.Fatal("cleanup-impaired failure with protocol result accepted")
	}
	if validCleanupImpairedFailure(Observation{
		ProcessStatus:  "timed_out",
		ProcessError:   "error",
		ProtocolStatus: "not_run",
	}) {
		t.Fatal("unsupported cleanup-impaired failure accepted")
	}

	for _, record := range []Observation{
		{ProtocolStatus: "valid", ExitCode: 2, CleanupComplete: true},
		{ProtocolStatus: "rejected", ExitCode: 0, CleanupComplete: true},
		{ProtocolStatus: "rejected", ExitCode: 2, CleanupComplete: true},
		{ProtocolStatus: "rejected", ExitCode: 3, CleanupComplete: true},
	} {
		if !validCompletedFailure(record) {
			t.Fatalf("completed failure rejected: %+v", record)
		}
	}
	if validCompletedFailure(Observation{
		ProtocolStatus:  "not_run",
		CleanupComplete: true,
	}) {
		t.Fatal("completed failure without protocol outcome accepted")
	}
	if validExitFailure(Observation{}) {
		t.Fatal("exit failure without process error accepted")
	}
}
