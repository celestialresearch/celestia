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
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
)

const (
	operationSplitDirectory  = "internal/operation/urlreference/"
	maxOperationSplitBytes   = 8 << 20
	operationSplitPackageSHA = "0d2f18ebe1deac1744f91fff7690df765e3a2ecd78e5ef8ff27d84c0b4e86b75"
	operationSplitSourceSHA  = "341c35c76b5d22dc361bf3d6e467f7d2afeddcfd6ab6ef0d5f4e08fc2e4f6ad6"
	operationSplitTargetSHA  = "1c558744a08c539475ac9253c207fa89dfad1ea24aaa7d098c2862ad7b9f4dfa"
)

var operationSplitOwners = map[string]string{
	"admission_windows_test.go":       "admission",
	"benchmark_windows_test.go":       "benchmark",
	"cancellation_windows_test.go":    "cancellation",
	"diagnostics_windows_test.go":     "diagnostics",
	"doc.go":                          "contract",
	"evidence_windows.go":             "evidence",
	"execution_windows_test.go":       "execution",
	"operation.go":                    "contract",
	"operation_unsupported.go":        "platform",
	"operation_unsupported_test.go":   "platform",
	"operation_windows.go":            "orchestration",
	"performance_decode.go":           "performance-report",
	"performance_report.go":           "performance-report",
	"performance_report_test.go":      "performance-report",
	"platform_windows.go":             "platform",
	"projection_windows.go":           "projection",
	"protocol_windows_test.go":        "protocol",
	"publication_windows_test.go":     "publication",
	"test_support_windows_test.go":    "test-support",
	"verification_windows.go":         "verification",
	"verification_windows_test.go":    "verification",
	"workload_corpus_windows_test.go": "performance-corpus",
}

func operationSplitDeclarationFindings(
	files []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	inventory, err := operationSplitInventoryFor(files, readFile, operationSplitOwners)
	if err != nil {
		return nil, err
	}
	var findings []string
	for label, pair := range map[string][2]string{
		"package, build and owner": {inventory.packages, operationSplitPackageSHA},
		"source":                   {inventory.sources, operationSplitSourceSHA},
		"test target":              {inventory.targets, operationSplitTargetSHA},
	} {
		if pair[0] != pair[1] {
			findings = append(findings, fmt.Sprintf(
				"%s: %s inventory differs: %s",
				strings.TrimSuffix(operationSplitDirectory, "/"), label, pair[0],
			))
		}
	}
	sort.Strings(findings)
	return findings, nil
}

func operationSplitInventoryFor(
	files []string,
	readFile func(string) ([]byte, error),
	owners map[string]string,
) (attemptSplitInventory, error) {
	direct := slices.DeleteFunc(slices.Clone(files), func(file string) bool {
		return path.Dir(file) != strings.TrimSuffix(operationSplitDirectory, "/")
	})
	return ownedGoSplitInventoryFor(direct, readFile, ownedGoSplitSpec{
		directory: operationSplitDirectory,
		packages:  []string{"urloperation"},
		owners:    owners,
		maxBytes:  maxOperationSplitBytes,
		label:     "URL operation",
	})
}
