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

//go:build linux && amd64

package main

import "os"

func runBootstrapMain() int {
	return runBootstrap(os.NewFile(4, "clone3-gate"), os.NewFile(3, "clone3-ready"),
		os.NewFile(5, "hostile-fixture"))
}
