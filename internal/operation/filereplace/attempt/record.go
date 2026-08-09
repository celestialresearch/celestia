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

package attempt

import "errors"

type State string

const (
	StateFailed        State = "failed"
	StateCancelled     State = "cancelled"
	StateVerified      State = "verified"
	StateIndeterminate State = "indeterminate"
)

var ErrInvalidTransition = errors.New("invalid file-replacement transition")

type Progress struct {
	Prepared        bool
	CommitAttempted bool
	NativeResult    bool
	NativeSucceeded bool
	Observed        bool
	Matched         bool
}

// Terminal derives the only truthful terminal state from retained progress.
func (p Progress) Terminal(cancelled bool) (State, error) {
	if !validProgress(p) {
		return "", ErrInvalidTransition
	}
	if p.CommitAttempted {
		if p.NativeResult && !p.NativeSucceeded {
			if p.Matched {
				return StateIndeterminate, nil
			}
			return StateFailed, nil
		}
		if p.Observed && p.Matched {
			return StateVerified, nil
		}
		return StateIndeterminate, nil
	}
	if cancelled {
		return StateCancelled, nil
	}
	return StateFailed, nil
}

func validProgress(p Progress) bool {
	if p.CommitAttempted && !p.Prepared || p.NativeResult && !p.CommitAttempted ||
		p.NativeSucceeded && !p.NativeResult || p.Observed && !p.CommitAttempted ||
		p.Matched && !p.Observed {
		return false
	}
	return true
}
