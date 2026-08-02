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

package main

import (
	"testing"
)

func TestInspectDocumentsRejectsInvalidJobs(t *testing.T) {
	t.Parallel()

	testInvalidDocuments(t, []invalidDocument{
		{
			name:  "jobs sequence",
			path:  "main.yml",
			input: "jobs: []",
			mode:  actionsMode,
			want:  "jobs must be a mapping",
		},
		{
			name:  "job scalar",
			path:  "main.yml",
			input: "jobs:\n  scan: invalid\n",
			mode:  actionsMode,
			want:  "job must be a mapping",
		},
		{
			name:  "services sequence",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    services: []\n",
			mode:  actionsMode,
			want:  "services must be a mapping",
		},
		{
			name:  "service scalar",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    services:\n      database: invalid\n",
			mode:  actionsMode,
			want:  "service must be a mapping",
		},
		{
			name:  "missing container image",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    container: {}\n",
			mode:  actionsMode,
			want:  "container image is missing",
		},
		{
			name:  "container image sequence",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    container:\n      image: []\n",
			mode:  actionsMode,
			want:  "container image must be scalar",
		},
	})
}

func TestInspectDocumentsRejectsInvalidSteps(t *testing.T) {
	t.Parallel()

	testInvalidDocuments(t, []invalidDocument{
		{
			name:  "steps mapping",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    steps: {}\n",
			mode:  actionsMode,
			want:  "steps must be a sequence",
		},
		{
			name:  "step scalar",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    steps:\n      - invalid\n",
			mode:  actionsMode,
			want:  "step must be a mapping",
		},
		{
			name:  "uses mapping",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    steps:\n      - uses: {}\n",
			mode:  actionsMode,
			want:  "action reference must be scalar",
		},
		{
			name:  "runs scalar",
			path:  "action.yml",
			input: "runs: invalid\n",
			mode:  actionsMode,
			want:  "runs must be a mapping",
		},
		{
			name:  "action image mapping",
			path:  "action.yml",
			input: "runs:\n  image: {}\n",
			mode:  actionsMode,
			want:  "action image must be scalar",
		},
		{
			name:  "action step reference mapping",
			path:  "action.yml",
			input: "runs:\n  steps:\n    - uses: {}\n",
			mode:  actionsMode,
			want:  "action reference must be scalar",
		},
		{
			name:  "service image mapping",
			path:  "main.yml",
			input: "jobs:\n  scan:\n    services:\n      database:\n        image: {}\n",
			mode:  actionsMode,
			want:  "container image must be scalar",
		},
	})
}
