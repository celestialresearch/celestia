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
	operationSplitPackageSHA = "9d0b7c75dd9064313946cdf21586fff6c90c8fd73f8c52a9c4ca040503037aa1"
	operationSplitSourceSHA  = "973b3b58a29c1ddb7a73578a94c7087a6136add5e8e2ee7f43730daaef9e519b"
	operationSplitTargetSHA  = "2701c52f99ecbe34941a4f62653c79c68065e4e07b7e022a0577cf089e4163af"
)

var operationSplitOwners = map[string]string{
	"admission_windows_test.go":                "admission",
	"benchmark_windows_test.go":                "benchmark",
	"cancellation_windows_test.go":             "cancellation",
	"diagnostics_windows_test.go":              "diagnostics",
	"doc.go":                                   "contract",
	"evidence_windows.go":                      "evidence",
	"execution_windows_test.go":                "execution",
	"operation.go":                             "contract",
	"operation_unsupported.go":                 "platform",
	"operation_unsupported_test.go":            "platform",
	"operation_windows.go":                     "orchestration",
	"performance_report_decoder_test.go":       "performance-report",
	"performance_output_windows_test.go":       "performance-output",
	"performance_report_model_test.go":         "performance-report",
	"performance_report_test.go":               "performance-report",
	"performance_campaign_unsupported_test.go": "performance-campaign",
	"performance_campaign_windows_test.go":     "performance-campaign",
	"platform_windows.go":                      "platform",
	"projection_windows.go":                    "projection",
	"protocol_windows_test.go":                 "protocol",
	"publication_windows_test.go":              "publication",
	"test_support_windows_test.go":             "test-support",
	"verification_windows.go":                  "verification",
	"verification_windows_test.go":             "verification",
	"workload_corpus_windows_test.go":          "performance-corpus",
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
