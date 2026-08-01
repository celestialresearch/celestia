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

package urlreference

import "testing"

func TestIsHexClasses(t *testing.T) {
	t.Parallel()

	for _, value := range []byte{'0', 'A', 'a', 'F', 'f'} {
		if !isHex(value) {
			t.Errorf("isHex(%q) = false", value)
		}
	}
	for _, value := range []byte{'/', 'G', 'g'} {
		if isHex(value) {
			t.Errorf("isHex(%q) = true", value)
		}
	}
}
