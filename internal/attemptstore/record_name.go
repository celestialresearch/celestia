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

import "strings"

func recordNames() []string {
	return []string{
		admittedFile,
		observationFile,
		recoveryFile,
		receiptFile,
		publicationFile,
	}
}

func temporaryRecordName(record, candidate string) bool {
	suffix, found := strings.CutPrefix(candidate, "."+record+".")
	if !found || len(suffix) != 32 {
		return false
	}
	for _, value := range suffix {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return true
}
