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

type durabilityResult struct {
	Outcome          string
	Reason           string
	CleanupAttempted bool
	CleanupComplete  bool
}

func unavailableDurability(reason string) durabilityResult {
	return durabilityResult{Outcome: "unavailable", Reason: reason}
}

func finishDurabilityCleanup(result durabilityResult, cleanupError error) durabilityResult {
	if !result.CleanupAttempted {
		result.CleanupAttempted = true
		result.CleanupComplete = cleanupError == nil
	} else if cleanupError != nil {
		result.CleanupComplete = false
	}
	return result
}
