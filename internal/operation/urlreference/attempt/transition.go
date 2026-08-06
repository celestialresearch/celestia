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

//go:build windows || (linux && amd64)

package attemptstore

func validateObservationTransition(record Observation) error {
	if validObservationTransition(record) {
		return nil
	}
	return ErrCorrupt
}

func validObservationTransition(record Observation) bool {
	switch record.TerminalStatus {
	case "verified":
		return validVerifiedObservation(record)
	case "executed_unverified":
		return validUnverifiedObservation(record)
	case "failed":
		return validFailedObservation(record)
	case "cancelled":
		return validCancelledObservation(record)
	case "timed_out":
		return validTimedOutObservation(record)
	default:
		return false
	}
}

func validCancelledObservation(record Observation) bool {
	return record.ProcessStatus == "cancelled" &&
		record.ProcessError != "" &&
		record.ProtocolStatus == "not_run" &&
		noVerification(record)
}

func validTimedOutObservation(record Observation) bool {
	return (record.ProcessStatus == "timed_out" ||
		record.ProcessStatus == "cancelled" ||
		record.ProcessStatus == "start_failed") &&
		record.ProcessError != "" &&
		record.ProtocolStatus == "not_run" &&
		noVerification(record) &&
		(record.ProcessStatus != "start_failed" ||
			record.ExitCode == 0 && noProcessStreams(record))
}

func validVerifiedObservation(record Observation) bool {
	return record.ProcessStatus == "completed" &&
		record.ProcessError == "" &&
		record.ExitCode == 0 &&
		record.CleanupComplete &&
		record.ProtocolStatus == "valid" &&
		record.VerificationID != "" &&
		record.VerificationVer != "" &&
		record.ExpectedOutput != "" &&
		record.VerificationPass
}

func validUnverifiedObservation(record Observation) bool {
	return record.ProcessStatus == "completed" &&
		record.ProcessError == "" &&
		record.ExitCode == 0 &&
		record.CleanupComplete &&
		record.ProtocolStatus == "valid" &&
		record.VerificationID != "" &&
		record.VerificationVer != "" &&
		record.ExpectedOutput != "" &&
		!record.VerificationPass
}

func validFailedObservation(record Observation) bool {
	if !noVerification(record) {
		return false
	}
	if !record.CleanupComplete {
		return validCleanupImpairedFailure(record)
	}
	switch record.ProcessStatus {
	case "completed":
		return validCompletedFailure(record)
	case "cleanup_failed":
		return validCleanupFailure(record)
	case "start_failed":
		return validStartFailure(record)
	case "exit_failed":
		return validExitFailure(record)
	case "output_overflow", "error_overflow":
		return validProcessFailure(record)
	default:
		return false
	}
}

func validCleanupImpairedFailure(record Observation) bool {
	if record.ProcessError == "" || record.ProtocolStatus != "not_run" {
		return false
	}
	switch record.ProcessStatus {
	case "completed", "exit_failed", "output_overflow", "error_overflow", "cleanup_failed":
		return true
	case "start_failed":
		return record.ExitCode == 0 && noProcessStreams(record)
	default:
		return false
	}
}

func validCompletedFailure(record Observation) bool {
	if record.ProcessError != "" || !record.CleanupComplete {
		return false
	}
	switch record.ProtocolStatus {
	case "valid":
		return record.ExitCode == 2
	case "rejected":
		return record.ExitCode == 0 ||
			record.ExitCode == 2 ||
			record.ExitCode == 3
	default:
		return false
	}
}

func validExitFailure(record Observation) bool {
	if record.ProcessError == "" || !record.CleanupComplete {
		return false
	}
	if record.ProtocolStatus == "valid" {
		return record.ExitCode == 3
	}
	return record.ProtocolStatus == "not_run"
}

func validCleanupFailure(record Observation) bool {
	return record.ProtocolStatus == "not_run" &&
		record.ProcessError != "" &&
		!record.CleanupComplete
}

func validStartFailure(record Observation) bool {
	return record.ProtocolStatus == "not_run" &&
		record.ProcessError != "" &&
		record.CleanupComplete &&
		record.ExitCode == 0 &&
		noProcessStreams(record)
}

func validProcessFailure(record Observation) bool {
	return record.ProtocolStatus == "not_run" &&
		record.ProcessError != "" &&
		record.CleanupComplete
}

func noVerification(record Observation) bool {
	return record.VerificationID == "" &&
		record.VerificationVer == "" &&
		record.ExpectedOutput == "" &&
		!record.VerificationPass
}

func noProcessStreams(record Observation) bool {
	return len(record.Stdout) == 0 && len(record.Stderr) == 0
}
