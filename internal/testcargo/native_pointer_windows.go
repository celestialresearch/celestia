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

//go:build windows && amd64

package testcargo

import "unsafe"

func nativePointer[T any](value *T) unsafe.Pointer {
	return unsafe.Pointer(value) // #nosec G103 -- Win32 requires a pointer to the typed native value.
}
