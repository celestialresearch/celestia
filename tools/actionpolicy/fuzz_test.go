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
	"bytes"
	"fmt"
	"testing"
)

func FuzzInspectWorkflow(f *testing.F) {
	f.Add([]byte("name: test\njobs: {}\n"))
	f.Add([]byte("name: test\npermissions: read-all\njobs: {}\n"))
	f.Add([]byte("name: &name test\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@0123456789012345678901234567890123456789\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxActionDocumentBytes {
			return
		}
		for _, mode := range []string{actionsMode, permissionsMode} {
			firstOutput, firstErr := inspectForFuzz(data, mode)
			secondOutput, secondErr := inspectForFuzz(data, mode)
			if firstOutput != secondOutput ||
				fmt.Sprint(firstErr) != fmt.Sprint(secondErr) {
				t.Fatalf("inspection is nondeterministic for mode %s", mode)
			}
			if len(firstOutput) > maxActionCorpusBytes {
				t.Fatalf("inspection output exceeds corpus bound for mode %s", mode)
			}
			firstOutput, firstErr = inspectStreamForFuzz(data, mode)
			secondOutput, secondErr = inspectStreamForFuzz(data, mode)
			if firstOutput != secondOutput ||
				fmt.Sprint(firstErr) != fmt.Sprint(secondErr) {
				t.Fatalf("stream inspection is nondeterministic for mode %s", mode)
			}
			if len(firstOutput) > maxActionCorpusBytes {
				t.Fatalf("stream output exceeds corpus bound for mode %s", mode)
			}
		}
	})
}

func inspectForFuzz(data []byte, mode string) (string, error) {
	var output bytes.Buffer
	err := inspect(document{
		path: ".github/workflows/fuzz.yml",
		data: data,
	}, mode, &output)
	return output.String(), err
}

func inspectStreamForFuzz(data []byte, mode string) (string, error) {
	var output bytes.Buffer
	err := inspectDocuments(bytes.NewReader(data), &output, mode, streamLimits{
		documents:  maxActionDocuments,
		pathBytes:  maxActionPathBytes,
		dataBytes:  maxActionDocumentBytes,
		totalBytes: maxActionCorpusBytes,
	})
	return output.String(), err
}
