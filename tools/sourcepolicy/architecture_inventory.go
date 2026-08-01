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
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"
	"strings"
)

func inventoryDigest(files []string) string {
	values := slices.Clone(files)
	sort.Strings(values)
	digest := sha256.Sum256([]byte(strings.Join(values, "\n") + "\n"))
	return fmt.Sprintf("%x", digest)
}

func equalStrings(actual, expected []string) bool {
	return slices.Equal(actual, expected)
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
