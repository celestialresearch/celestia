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

func expectedRootDirectories() []string {
	return []string{".cargo", ".github", "cmd", "docs", "internal", "policies", "testdata", "tools", "worker"}
}

func expectedRootFiles() []string {
	return []string{
		".editorconfig", ".gitattributes", ".gitignore", ".golangci.yml",
		"AGENTS.md", "Cargo.lock", "Cargo.toml", "LICENSE", "README.md",
		"deny.toml", "go.mod", "go.sum", "rust-toolchain.toml",
	}
}

func expectedProhibitedSegments() []string {
	return []string{
		"base", "common", "component", "components", "core", "extra",
		"extended", "framework", "general", "helper", "helpers", "legacy", "migration",
		"manager", "misc", "module", "modules", "platform", "platforms",
		"service", "services", "shared", "temp", "temporary", "util", "utils",
	}
}

func expectedPackages() []string {
	return []string{
		"internal/attemptstore", "internal/processsupervision", "internal/urladmission",
		"internal/urloperation", "internal/urlreferencev1", "internal/workerprotocolv1",
		"tools/actionpolicy", "tools/sourcepolicy",
	}
}

func expectedRustPackages() []string {
	return []string{"worker/qualification-fixtures", "worker/url-reference"}
}

func expectedScripts() []string {
	return []string{
		".github/scripts/actioncheck.sh", ".github/scripts/actioncheck_test.sh",
		".github/scripts/changecheck.sh", ".github/scripts/changecheck_test.sh",
		".github/scripts/coveragecheck.sh", ".github/scripts/currencycheck.sh",
		".github/scripts/currencycheck_test.sh", ".github/scripts/depguardcheck.sh",
		".github/scripts/devcheck.sh", ".github/scripts/dragonfly-bootstrap.sh",
		".github/scripts/licencecheck.sh", ".github/scripts/modcheck.sh",
		".github/scripts/platformlint.sh", ".github/scripts/policycheck.sh",
		".github/scripts/rustcheck.sh", ".github/scripts/testcheck.sh",
		".github/scripts/testcheck_test.sh", ".github/scripts/verification_test.sh",
		".github/scripts/windows-shellcheck.ps1",
	}
}

func expectedImportRules() []string {
	return []string{
		"command-imports-operation-subpackage", "execution-imports-operation",
		"operation-imports-operation", "operation-subpackage-imports-root",
		"production-imports-assurance", "runtime-imports-tools", "runtime-imports-worker",
	}
}

func expectedMigrationRoots() []architectureMigrationRoot {
	return []architectureMigrationRoot{
		{Path: "internal/attemptstore", Count: 48, Digest: "b33f419cd6d54a697c18f95cb23c156debc5a8cc1facc2acbe6d3d7541d73a54", Destination: "internal/operation/urlreference/attempt", Slice: "CEL-STRUCT-004D", Expiry: "CEL-STRUCT-004D"},
		{Path: "internal/processsupervision", Count: 19, Digest: "6f3533b58c7efd95e2948ebaf8f6fa956b81454204f15ac29520086cecc87fe8", Destination: "internal/execution/supervision", Slice: "CEL-STRUCT-003", Expiry: "CEL-STRUCT-003"},
		{Path: "internal/urladmission", Count: 2, Digest: "7f3df87edbfd1b3f0a79f8778bf495b45ec31a806b73a9c9f34280131e00bbf5", Destination: "internal/operation/urlreference/admission", Slice: "CEL-STRUCT-004C", Expiry: "CEL-STRUCT-004C"},
		{Path: "internal/urloperation", Count: 5, Digest: "9ea53ceaa57bb11f17df5e1da4d30f9d174e0d9cb38eef41ebd22cf7779d0755", Destination: "internal/operation/urlreference", Slice: "CEL-STRUCT-004E", Expiry: "CEL-STRUCT-004E"},
		{Path: "internal/urlreferencev1", Count: 5, Digest: "1e87214904512a3f9f63d81335271504eb2cbaba583fa5d1d86aee41177f35bd", Destination: "internal/operation/urlreference/transform", Slice: "CEL-STRUCT-004A", Expiry: "CEL-STRUCT-004A"},
		{Path: "internal/workerprotocolv1", Count: 3, Digest: "bb6d19a43ceb0e953687c4713eae36b70e7bb328a685a9381fec0f4c43154859", Destination: "internal/operation/urlreference/protocol", Slice: "CEL-STRUCT-004B", Expiry: "CEL-STRUCT-004B"},
	}
}
