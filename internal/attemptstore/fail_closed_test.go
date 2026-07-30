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

package attemptstore

import "testing"

func TestEvidencePathsFailClosed(t *testing.T) {
	accepted, _ := testAccepted(t)
	invalid := "invalid\x00path"
	validStore := newTestStore(t)

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "attempt publication root",
			run: func() error {
				_, err := (&Store{root: invalid}).inspectPublishedPath(
					invalid,
					accepted.Request.AttemptID,
				)
				return err
			},
		},
		{
			name: "evidence publication root",
			run: func() error {
				_, err := validStore.inspectPublishedPath(
					invalid,
					accepted.Request.AttemptID,
				)
				return err
			},
		},
		{
			name: "bundle enumeration",
			run: func() error {
				return validateBundleFiles(invalid, observationFile, true)
			},
		},
		{
			name: "path existence",
			run: func() error {
				_, err := pathExists(invalid)
				return err
			},
		},
		{
			name: "attempt lookup",
			run: func() error {
				_, err := (&Store{root: invalid}).attemptPath(
					accepted.Request.AttemptID,
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("invalid evidence path accepted")
			}
		})
	}
}
