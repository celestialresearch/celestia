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

//go:build windows

package attemptstore

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

func recordTempName(name string) (string, error) {
	return recordTempNameWith(name, rand.Reader)
}

func recordTempNameWith(name string, randomness io.Reader) (string, error) {
	var identity [16]byte
	if _, err := io.ReadFull(randomness, identity[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(".%s.%x", name, identity), nil
}

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
