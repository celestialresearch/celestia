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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package attemptstore

import (
	"os"
	"syscall"
)

func secureEvidenceParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok ||
		int64(stat.Uid) != int64(os.Geteuid()) ||
		info.Mode().Perm()&0o022 != 0 {
		return ErrCorrupt
	}
	return nil
}
