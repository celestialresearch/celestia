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
	"errors"
	"os"
)

func evaluateArchitectureFixture(mutation string) string {
	if architectureFixtureRejected(mutation) {
		return "reject"
	}
	return "accept"
}

func architectureFixtureRejected(mutation string) bool {
	check, exists := architectureFixtureChecks[mutation]
	if !exists {
		return false
	}
	return check(validArchitectureFixturePolicy())
}

var architectureFixtureChecks = map[string]func(architecturePolicy) bool{
	"none": func(architecturePolicy) bool { return false },
	"operation-imports-operation": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("internal/operation/alpha", architectureModule+"/internal/operation/beta") != ""
	},
	"subpackage-imports-root": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("internal/operation/alpha/transform", architectureModule+"/internal/operation/alpha") != ""
	},
	"execution-imports-operation": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("internal/execution/supervision", architectureModule+"/internal/operation/alpha") != ""
	},
	"production-imports-assurance": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("internal/operation/alpha", "celestia.research/assurance/check") != ""
	},
	"runtime-imports-tools": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("internal/operation/alpha", architectureModule+"/tools/sourcepolicy") != ""
	},
	"runtime-imports-worker": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("internal/operation/alpha", architectureModule+"/worker/url-reference") != ""
	},
	"command-imports-subpackage": func(architecturePolicy) bool {
		return forbiddenArchitectureImport("cmd/celestia", architectureModule+"/internal/operation/alpha/transform") != ""
	},
	"undeclared-command": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"cmd/example/main.go"}, policy)
	},
	"vague-platform-directory": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"internal/platform/file.go"}, policy)
	},
	"vague-platforms-directory": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"internal/platforms/file.go"}, policy)
	},
	"unapproved-root": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"application/file.go"}, policy)
	},
	"missing-package-comment": missingPackageCommentRejected,
	"stale-module": func(architecturePolicy) bool {
		return validateCurrentModule(func(string) ([]byte, error) {
			return []byte("module obsolete.example/module\n"), nil
		}, architectureModule) != nil
	},
	"forwarding-obsolete-package": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"internal/obsolete/forward.go"}, policy)
	},
	"undeclared-file-exception": func(policy architecturePolicy) bool {
		policy.FileExceptions = []architectureExcept{{Path: "internal/example.go"}}
		return validateArchitecturePolicy(policy) != nil
	},
	"missing-policy": func(architecturePolicy) bool {
		return runArchitecturePolicy(
			discardArchitectureFixtureWriter{}, func() ([]string, error) { return nil, nil },
			noExecutableSources,
			func(string) ([]byte, error) { return nil, errors.New("missing") },
		) != 0
	},
	"malformed-policy": func(architecturePolicy) bool {
		_, err := decodeArchitecturePolicy([]byte("{"))
		return err != nil
	},
	"policy-permits-forbidden-edge": func(policy architecturePolicy) bool {
		policy.ImportRules = policy.ImportRules[:len(policy.ImportRules)-1]
		return validateArchitecturePolicy(policy) != nil
	},
	"root-common-helper": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"common/file.go"}, policy)
	},
	"internal-utils": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"internal/utils/file.go"}, policy)
	},
	"root-services": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"services/file.go"}, policy)
	},
	"root-src": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"src/file.go"}, policy)
	},
	"worker-private-key-path": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"worker/example/private-key.pem"}, policy)
	},
	"migration-additional-file": func(policy architecturePolicy) bool {
		entry := policy.MigrationRoots[0]
		files := append([]string(nil), entry.Inventory...)
		files = append(files, entry.Path+"/unexpected.go")
		return len(architectureMigrationFindings(files, policy)) != 0
	},
	"unregistered-flat-package": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"internal/newpackage/file.go"}, policy)
	},
	"unregistered-testdata-package": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"tools/sourcepolicy/testdata/rogue/main.go"}, policy)
	},
	"unregistered-rust-package": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{
			"worker/rogue/Cargo.toml", "worker/rogue/src/main.rs",
		}, policy)
	},
	"unregistered-script": func(policy architecturePolicy) bool {
		return hasArchitecturePathFinding([]string{"tools/rogue/run.sh"}, policy)
	},
	"migration-wildcard-entry": func(policy architecturePolicy) bool {
		policy.MigrationRoots[0].Path = "internal/*"
		return validateArchitecturePolicy(policy) != nil
	},
	"migration-parent-entry": func(policy architecturePolicy) bool {
		policy.MigrationRoots[0].Path = "internal"
		return validateArchitecturePolicy(policy) != nil
	},
	"migration-expired-entry": func(policy architecturePolicy) bool {
		policy.MigrationRoots[0].Expiry = "CEL-STRUCT-001"
		return validateArchitecturePolicy(policy) != nil
	},
	"migrated-path-recreated": func(architecturePolicy) bool {
		policy := validArchitectureFixturePolicy()
		policy.RetiredMigration = []string{"internal/attemptstore"}
		return hasArchitecturePathFinding([]string{"internal/attemptstore/store.go"}, policy)
	},
}

func missingPackageCommentRejected(policy architecturePolicy) bool {
	policy.Packages = []string{"internal/example"}
	findings, err := packageDocumentationFindings(
		[]string{"internal/example/example.go"}, policy,
		func(string) ([]byte, error) { return []byte("package example\n"), nil },
	)
	return err == nil && len(findings) != 0
}

type discardArchitectureFixtureWriter struct{}

func (discardArchitectureFixtureWriter) Write(value []byte) (int, error) {
	return len(value), nil
}

func hasArchitecturePathFinding(files []string, policy architecturePolicy) bool {
	return len(architecturePathFindings(files, nil, policy)) != 0
}

func validArchitectureFixturePolicy() architecturePolicy {
	data, err := os.ReadFile("../../policies/architecture.json")
	if err != nil {
		panic(err)
	}
	policy, err := decodeArchitecturePolicy(data)
	if err != nil {
		panic(err)
	}
	return policy
}
