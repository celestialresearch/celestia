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
	"errors"
	"strings"
	"testing"
)

func TestModuleReplacementPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		source  string
		readErr error
		want    string
	}{
		"none":      {source: "module fixture.invalid/root\n\ngo 1.26.5\n"},
		"local":     {source: "module fixture.invalid/root\n\ngo 1.26.5\n\nreplace fixture.invalid/a => ./a\n", want: "replacements are prohibited"},
		"versioned": {source: "module fixture.invalid/root\n\ngo 1.26.5\n\nreplace mirror.invalid/a => celestia.research/assurance v1.0.0\n", want: "replacements are prohibited"},
		"malformed": {source: "not a module", want: "parse Go module"},
		"read":      {readErr: errors.New("read failure"), want: "read failure"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := rejectModuleReplacements(
				[]string{"go.mod"},
				func(string) ([]byte, error) { return []byte(test.source), test.readErr },
			)
			if test.want == "" && err != nil {
				t.Fatalf("replacement policy error = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("replacement policy error = %v, want %q", err, test.want)
			}
		})
	}
}
