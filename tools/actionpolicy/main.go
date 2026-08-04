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
	"fmt"
	"io"
	"os"
)

const (
	actionsMode     = "actions"
	permissionsMode = "permissions"
	verifyMode      = "verify"

	maxActionDocuments     = 256
	maxActionPathBytes     = 4096
	maxActionDocumentBytes = 1 << 20
	maxActionCorpusBytes   = 16 << 20
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, input io.Reader, output io.Writer, errorOutput io.Writer) int {
	if len(args) != 1 ||
		(args[0] != actionsMode && args[0] != permissionsMode &&
			args[0] != verifyMode) {
		if _, err := fmt.Fprintln(
			errorOutput,
			"Usage: actionpolicy actions|permissions|verify",
		); err != nil {
			return 1
		}
		return 2
	}
	limits := streamLimits{
		documents:  maxActionDocuments,
		pathBytes:  maxActionPathBytes,
		dataBytes:  maxActionDocumentBytes,
		totalBytes: maxActionCorpusBytes,
	}
	if err := inspectDocuments(input, output, args[0], limits); err != nil {
		if _, writeErr := fmt.Fprintln(errorOutput, err); writeErr != nil {
			return 1
		}
		return 1
	}
	return 0
}
