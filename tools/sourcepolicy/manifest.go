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
	governedManifestSHA   = "d8bf9eeeeecfabc884ccf7944c1fb91ef7dc80c3330304c7f0b00f5f9730caa0"
	structureManifestPath = "docs/contracts/cel_struct_001.json"
	structureManifestSHA  = "e062137f91713d0a9176d1af20720b20bf7c4ebfbc88ee0bf70a4d6316c490cc"
	executionManifestPath = "docs/contracts/cel_struct_003.json"
	executionManifestSHA  = "1c0d68f1d6ea11a29c04dffe4fa15978732bc39c136d2d1fb2992be6c32bafb5"
	transformManifestPath = "docs/contracts/cel_struct_004a.json"
	transformManifestSHA  = "b380bc3c6734ad11146ebda494a4c35318b3f521150ebf6283d7a933f53e8039"
	protocolManifestPath  = "docs/contracts/cel_struct_004b.json"
	protocolManifestSHA   = "ab13200a42669cb82115d2def997bcc1d55b4f62e031e6eb8a5de96ab291228d"
	admissionManifestPath = "docs/contracts/cel_struct_004c.json"
	admissionManifestSHA  = "1c5d5545097ecd0ff1f46b7c7a007f684006e18ad5cc724be76f0f53bae69206"
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
		{protocolManifestPath, protocolManifestSHA},
		{admissionManifestPath, admissionManifestSHA},
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
