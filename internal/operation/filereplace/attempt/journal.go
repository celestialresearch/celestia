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

import "time"

const SchemaVersion = "celestia.file-replace.attempt.v1"

type Intent struct {
	Schema            string    `json:"schema_version"`
	AttemptID         string    `json:"attempt_id"`
	AdmittedAt        time.Time `json:"admitted_at"`
	Target            string    `json:"target"`
	ExpectedSHA256    string    `json:"expected_sha256"`
	ReplacementSHA256 string    `json:"replacement_sha256"`
	ReplacementLength int64     `json:"replacement_length"`
	Temporary         string    `json:"temporary"`
}

type Checkpoint struct {
	Schema    string `json:"schema_version"`
	AttemptID string `json:"attempt_id"`
}

type Effect struct {
	Schema          string `json:"schema_version"`
	AttemptID       string `json:"attempt_id"`
	NativeSucceeded bool   `json:"native_succeeded"`
}

type Verification struct {
	Schema         string `json:"schema_version"`
	AttemptID      string `json:"attempt_id"`
	Observed       bool   `json:"observed"`
	ObservedSHA256 string `json:"observed_sha256"`
	ObservedLength int64  `json:"observed_length"`
	Matched        bool   `json:"matched"`
}

type Receipt struct {
	Schema          string `json:"schema_version"`
	AttemptID       string `json:"attempt_id"`
	State           State  `json:"state"`
	CleanupComplete bool   `json:"cleanup_complete"`
	IntentSHA256    string `json:"intent_sha256"`
	EffectSHA256    string `json:"effect_sha256,omitempty"`
	VerificationSHA string `json:"verification_sha256,omitempty"`
}
