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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const (
	governedManifestPath  = "docs/contracts/governed_url_reference_v1.json"
	governedManifestSHA   = "aff0ab1df517151da1445093c61b7d05fce148c7465094936b99a91025e03533"
	structureManifestPath = "docs/contracts/cel_struct_001.json"
	structureManifestSHA  = "e062137f91713d0a9176d1af20720b20bf7c4ebfbc88ee0bf70a4d6316c490cc"
	executionManifestPath = "docs/contracts/cel_struct_003.json"
	executionManifestSHA  = "8b59e1fde2adad247eb72b5fb6e533dff8cb717f144d1e13552579c0f33eb47c"
)

func runManifestPolicy(stderr io.Writer, readFile func(string) ([]byte, error)) int {
	manifests := []struct {
		path   string
		digest string
	}{
		{governedManifestPath, governedManifestSHA},
		{structureManifestPath, structureManifestSHA},
		{executionManifestPath, executionManifestSHA},
	}
	for _, manifest := range manifests {
		if manifestPolicyStatus(stderr, readFile, manifest.path, manifest.digest) != 0 {
			return 1
		}
	}
	return 0
}

func manifestPolicyStatus(
	stderr io.Writer,
	readFile func(string) ([]byte, error),
	path string,
	expected string,
) int {
	data, err := readFile(path)
	if err != nil {
		return writeManifestError(stderr, "read governed manifest: "+err.Error())
	}
	if !json.Valid(data) {
		return writeManifestError(stderr, "governed manifest is not valid JSON")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return writeManifestError(stderr, "governed manifest differs from its reviewed form")
	}
	return 0
}

func writeManifestError(stderr io.Writer, message string) int {
	if _, err := fmt.Fprintln(stderr, message); err != nil {
		return 1
	}
	return 1
}
