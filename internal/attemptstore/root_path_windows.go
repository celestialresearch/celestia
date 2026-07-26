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

import "path/filepath"

func validEvidenceRootPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	volume := filepath.VolumeName(path)
	return len(volume) == 2 &&
		((volume[0] >= 'A' && volume[0] <= 'Z') ||
			(volume[0] >= 'a' && volume[0] <= 'z')) &&
		volume[1] == ':'
}
