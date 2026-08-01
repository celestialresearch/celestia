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
	governedManifestSHA   = "a22945a95c40129b37b8a5851e05743c3424a8fcb09297edb79bdb140b3879c7"
	structureManifestPath = "docs/contracts/cel_struct_001.json"
	structureManifestSHA  = "e062137f91713d0a9176d1af20720b20bf7c4ebfbc88ee0bf70a4d6316c490cc"
	executionManifestPath = "docs/contracts/cel_struct_003.json"
	executionManifestSHA  = "1c0d68f1d6ea11a29c04dffe4fa15978732bc39c136d2d1fb2992be6c32bafb5"
	transformManifestPath = "docs/contracts/cel_struct_004a.json"
	transformManifestSHA  = "b380bc3c6734ad11146ebda494a4c35318b3f521150ebf6283d7a933f53e8039"
)

func runManifestPolicy(stderr io.Writer, readFile func(string) ([]byte, error)) int {
	manifests := []struct {
		path   string
		digest string
	}{
		{governedManifestPath, governedManifestSHA},
		{structureManifestPath, structureManifestSHA},
		{executionManifestPath, executionManifestSHA},
		{transformManifestPath, transformManifestSHA},
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
