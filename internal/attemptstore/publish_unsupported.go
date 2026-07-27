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

//go:build js || plan9 || wasip1

package attemptstore

import "os"

func publishFile(_, _, _ string) error {
	return ErrUnsupported
}

func publishDirectory(_, _, _ string) error {
	return ErrUnsupported
}

func secureEvidenceTree(_ string) error {
	return ErrUnsupported
}

func secureEvidenceFile(_ string) error {
	return ErrUnsupported
}

func createEvidenceDirectory(_ string) error {
	return ErrUnsupported
}

func pathIsLinked(_ string, _ os.FileInfo) bool {
	return true
}

func confirmPublication(_ string) error {
	return ErrUnsupported
}

func repairInterruptedRecords(string) error {
	return ErrUnsupported
}
