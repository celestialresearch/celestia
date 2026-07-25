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

func BenchmarkTransform(b *testing.B) {
	for range b.N {
		output, err := Transform(
			"https://sub.example.test:8443/path?v=1.2#section",
			Defang,
		)
		if err != nil || output == "" {
			b.Fatalf("transform: output=%q error=%v", output, err)
		}
	}
}
