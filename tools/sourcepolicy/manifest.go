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
	governedManifestSHA   = "a9afb81c9c40d5e35cab4833bc04bba809c3ae0590a99e035ed28a81453b23b3"
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
	attemptManifestPath   = "docs/contracts/cel_struct_004d.json"
	attemptManifestSHA    = "3f9066e3b143ec71f6575665be4c05bd0510e6623dcb3aaf72f2cdc460c73ab6"
	operationManifestPath = "docs/contracts/cel_struct_004e.json"
	operationManifestSHA  = "448e55e1a22b942e7dd3bd4e96432ed4b299b90ef553ae9a3e029be53c618265"
	layoutManifestPath    = "docs/contracts/cel_struct_005.json"
	layoutManifestSHA     = "58b4e70d9b47d907f8b5cbdde163204c82d6633692ac3d7b610f9cd8ff4a8097"
	splitManifestPath     = "docs/contracts/cel_split_001.json"
	splitManifestSHA      = "7985a96078eecb71200cfe7fabbdc5c8368afd0e7ef17e9d1a996868fc401c5d"
	attemptSplitPath      = "docs/contracts/cel_split_002.json"
	attemptSplitSHA       = "9c9ccaa4732cb47123e80148d5b7611644c98df7103489c89bd8aa59af997269"
	supervisionSplitPath  = "docs/contracts/cel_split_003.json"
	supervisionSplitSHA   = "347b056e760c122cabe9f970c35cbf0e7abcbeab9d9e5781bb34768d6ebf3305"
	operationSplitPath    = "docs/contracts/cel_split_004.json"
	operationSplitSHA     = "061579d73feef02b22ffa99ea4ac39bdeaf12ec3d4104cfb5b90d776e6197660"
	sourcePolicySplitPath = "docs/contracts/cel_split_005.json"
	sourcePolicySplitSHA  = "7df8b83274019cc1e857bd1707f5b436c8eb8e28341cb0344aaddee6697afcb9"
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
		{attemptManifestPath, attemptManifestSHA},
		{operationManifestPath, operationManifestSHA},
		{layoutManifestPath, layoutManifestSHA},
		{splitManifestPath, splitManifestSHA},
		{attemptSplitPath, attemptSplitSHA},
		{supervisionSplitPath, supervisionSplitSHA},
		{operationSplitPath, operationSplitSHA},
		{sourcePolicySplitPath, sourcePolicySplitSHA},
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
