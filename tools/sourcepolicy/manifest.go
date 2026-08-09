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
	fileReplaceManifestPath = "docs/contracts/governed_file_replace_v1.json"
	fileReplaceManifestSHA  = "96a9a4a1ed6466abf5533e47637540b5c3b548543fea8fa4ad007b36c4db6c8b"
	governedManifestPath    = "docs/contracts/governed_url_reference_v1.json"
	governedManifestSHA     = "a9afb81c9c40d5e35cab4833bc04bba809c3ae0590a99e035ed28a81453b23b3"
	performanceManifestPath = "docs/contracts/governed_url_reference_performance_v1.json"
	performanceManifestSHA  = "969733e86240827e8d68f24323af92039b884ee836f876992d8ad444a3b19586"
	structureManifestPath   = "docs/contracts/cel_struct_001.json"
	structureManifestSHA    = "e062137f91713d0a9176d1af20720b20bf7c4ebfbc88ee0bf70a4d6316c490cc"
	executionManifestPath   = "docs/contracts/cel_struct_003.json"
	executionManifestSHA    = "1c0d68f1d6ea11a29c04dffe4fa15978732bc39c136d2d1fb2992be6c32bafb5"
	transformManifestPath   = "docs/contracts/cel_struct_004a.json"
	transformManifestSHA    = "b380bc3c6734ad11146ebda494a4c35318b3f521150ebf6283d7a933f53e8039"
	protocolManifestPath    = "docs/contracts/cel_struct_004b.json"
	protocolManifestSHA     = "ab13200a42669cb82115d2def997bcc1d55b4f62e031e6eb8a5de96ab291228d"
	admissionManifestPath   = "docs/contracts/cel_struct_004c.json"
	admissionManifestSHA    = "1c5d5545097ecd0ff1f46b7c7a007f684006e18ad5cc724be76f0f53bae69206"
	attemptManifestPath     = "docs/contracts/cel_struct_004d.json"
	attemptManifestSHA      = "3f9066e3b143ec71f6575665be4c05bd0510e6623dcb3aaf72f2cdc460c73ab6"
	operationManifestPath   = "docs/contracts/cel_struct_004e.json"
	operationManifestSHA    = "448e55e1a22b942e7dd3bd4e96432ed4b299b90ef553ae9a3e029be53c618265"
	layoutManifestPath      = "docs/contracts/cel_struct_005.json"
	layoutManifestSHA       = "58b4e70d9b47d907f8b5cbdde163204c82d6633692ac3d7b610f9cd8ff4a8097"
	splitManifestPath       = "docs/contracts/cel_split_001.json"
	splitManifestSHA        = "7985a96078eecb71200cfe7fabbdc5c8368afd0e7ef17e9d1a996868fc401c5d"
	attemptSplitPath        = "docs/contracts/cel_split_002.json"
	attemptSplitSHA         = "05e28c3d3d3a708e9c0be7c38e0217ea6492647bfe285415f98135696f50a89b"
	supervisionSplitPath    = "docs/contracts/cel_split_003.json"
	supervisionSplitSHA     = "347b056e760c122cabe9f970c35cbf0e7abcbeab9d9e5781bb34768d6ebf3305"
	operationSplitPath      = "docs/contracts/cel_split_004.json"
	operationSplitSHA       = "061579d73feef02b22ffa99ea4ac39bdeaf12ec3d4104cfb5b90d776e6197660"
	sourcePolicySplitPath   = "docs/contracts/cel_split_005.json"
	sourcePolicySplitSHA    = "7df8b83274019cc1e857bd1707f5b436c8eb8e28341cb0344aaddee6697afcb9"
	policyTestSplitPath     = "docs/contracts/cel_split_006.json"
	policyTestSplitSHA      = "c84189634b24f886bdbbc662b4879a37eea066668aebb59c067e5c8f577bec2c"
	assuranceSplitPath      = "docs/contracts/cel_split_007.json"
	assuranceSplitSHA       = "9c4f5785d284471430c5045d50ebcafd14f7f64dfc6c704c6799985b769bddd2"
	freezeSplitPath         = "docs/contracts/cel_split_008.json"
	freezeSplitSHA          = "5a82cf664db889462ab050c2585ef9130fd117acda5703f07f85d38fb88e1c6a"
	linuxFeasibilityPath    = "docs/contracts/cel_plat_linux_amd64_feas_001.json"
	linuxFeasibilitySHA     = "e8d6ac4050fe5d76ce08d44a8ae11d596319f1c66cabff18b6bc5e3e4068cda6"
)

func runManifestPolicy(stderr io.Writer, readFile func(string) ([]byte, error)) int {
	manifests := []struct {
		path   string
		digest string
	}{
		{fileReplaceManifestPath, fileReplaceManifestSHA},
		{governedManifestPath, governedManifestSHA},
		{performanceManifestPath, performanceManifestSHA},
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
		{policyTestSplitPath, policyTestSplitSHA},
		{assuranceSplitPath, assuranceSplitSHA},
		{freezeSplitPath, freezeSplitSHA},
		{linuxFeasibilityPath, linuxFeasibilitySHA},
	}
	status := 0
	for _, manifest := range manifests {
		if manifestPolicyStatus(stderr, readFile, manifest.path, manifest.digest) != 0 {
			status = 1
		}
	}
	return status
}

func manifestPolicyStatus(
	stderr io.Writer,
	readFile func(string) ([]byte, error),
	path string,
	expected string,
) int {
	data, err := readFile(path)
	if err != nil {
		return writeManifestError(stderr, path+": read governed manifest: "+err.Error())
	}
	if !json.Valid(data) {
		return writeManifestError(stderr, path+": governed manifest is not valid JSON")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return writeManifestError(stderr, path+": governed manifest differs from its reviewed form")
	}
	return 0
}

func writeManifestError(stderr io.Writer, message string) int {
	if _, err := fmt.Fprintln(stderr, message); err != nil {
		return 1
	}
	return 1
}
