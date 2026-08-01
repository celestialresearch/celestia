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
		"internal/execution/supervision",
		"internal/operation/urlreference",
		"internal/operation/urlreference/admission", "internal/operation/urlreference/attempt",
		"internal/operation/urlreference/protocol", "internal/operation/urlreference/transform",
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

func expectedProhibitedPaths() []string {
	return []string{
		"internal/processsupervision", "internal/urlreferencev1", "internal/workerprotocolv1",
		"internal/urladmission", "internal/attemptstore", "internal/urloperation",
	}
}
