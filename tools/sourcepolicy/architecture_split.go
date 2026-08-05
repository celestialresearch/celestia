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
	"strconv"
	"strings"
)

type splitDirectory struct {
	path  string
	files []string
}

func splitDirectories() []splitDirectory {
	directories := []splitDirectory{
		{
			path: "internal/operation/urlreference/transform",
			files: []string{
				"benchmark_test.go", "conformance_test.go", "doc.go", "hex_test.go",
				"host.go", "parse.go", "text.go", "transform.go", "urlreference_test.go",
			},
		},
		{
			path: "internal/operation/urlreference/protocol",
			files: []string{
				"benchmark_test.go", "doc.go", "frame.go", "frame_test.go", "fuzz_test.go",
				"protocol.go", "request.go", "request_test.go", "response.go", "response_test.go",
			},
		},
		{
			path: "internal/operation/urlreference/admission",
			files: []string{
				"admission.go", "admission_test.go", "doc.go",
			},
		},
		{
			path: "worker/url-reference/src",
			files: []string{
				"grammar.rs", "main.rs", "request.rs", "response.rs", "tests/grammar.rs",
				"tests/mod.rs", "tests/request.rs", "tests/response.rs", "tests/transform.rs",
				"transform.rs",
			},
		},
		{
			path: "internal/operation/urlreference/attempt",
			files: []string{
				"acl_fault_windows_test.go", "acl_windows.go", "acl_windows_test.go",
				"admitted_binding_test.go",
				"contract.go", "decision_invariants_test.go", "doc.go", "fail_closed_test.go",
				"identity_test.go", "inspect.go", "inspect_integrity_test.go", "inspect_test.go",
				"inspection_concurrency_test.go", "lock.go", "lock_fail_closed_test.go",
				"lock_fault_injection_windows_test.go", "lock_root.go", "lock_root_test.go",
				"lock_test.go", "lock_windows.go", "lock_windows_test.go",
				"observation_validation.go", "observation_validation_test.go", "ownership.go",
				"ownership_test.go", "paths.go", "paths_fault_test.go", "platform.go",
				"publish.go", "publish_fault_windows_test.go", "publish_result_test.go",
				"publish_test.go", "publish_windows.go", "publish_windows_test.go", "record.go",
				"record_fault_windows_test.go", "record_fuzz_test.go", "record_io.go",
				"record_io_test.go", "record_name.go", "record_name_test.go",
				"record_recovery_windows_test.go", "record_validation.go",
				"record_validation_test.go", "record_windows.go", "recover.go",
				"recovery_cleanup_test.go", "recovery_fault_test.go",
				"recovery_interruption_windows_test.go", "recovery_test.go",
				"repair_fault_windows_test.go", "repair_windows.go", "request_v1.go",
				"request_v1_test.go", "root.go",
				"root_fault_test.go", "root_parent_windows.go", "root_path_windows.go",
				"root_path_windows_test.go", "stage.go", "staging_fault_windows_test.go",
				"staging_test.go", "store.go", "store_fault_test.go", "store_test.go",
				"store_unsupported.go", "store_unsupported_test.go", "terminal.go",
				"terminal_fault_test.go",
				"transition.go", "transition_test.go",
			},
		},
		{
			path: "internal/operation/urlreference",
			files: []string{
				"admission_windows_test.go", "benchmark_windows_test.go",
				"cancellation_windows_test.go", "diagnostics_windows_test.go", "doc.go",
				"evidence_windows.go", "execution_windows_test.go", "operation.go",
				"operation_unsupported.go", "operation_unsupported_test.go",
				"operation_windows.go", "platform_windows.go", "projection_windows.go",
				"protocol_windows_test.go", "publication_windows_test.go",
				"test_support_windows_test.go", "verification_windows.go",
				"verification_windows_test.go", "workload_corpus_windows_test.go",
				"performance_campaign_unsupported_test.go", "performance_campaign_windows_test.go",
				"performance_report_decoder_test.go", "performance_output_windows_test.go",
				"performance_report_model_test.go", "performance_report_test.go",
			},
		},
	}
	return append(directories, policySplitDirectories()...)
}

func policySplitDirectories() []splitDirectory {
	return []splitDirectory{
		{path: "tools/sourcepolicy", files: sourcePolicySplitFiles()},
		{path: "tools/actionpolicy", files: actionPolicySplitFiles()},
	}
}

func splitSourcePathFindings(files []string) []string {
	allowed := splitSourceSet()
	obsolete := stringSet([]string{
		"internal/operation/urlreference/transform/urlreference.go",
		"internal/operation/urlreference/protocol/protocol_test.go",
		"worker/url-reference/src/tests.rs",
		"worker/url-reference/src/protocol.rs",
		"worker/url-reference/src/tests/protocol.rs",
		"internal/operation/urlreference/attempt/publication_test.go",
		"internal/operation/urlreference/attempt/records.go",
		"internal/operation/urlreference/attempt/records_transition_test.go",
		"internal/operation/urlreference/operation_windows_test.go",
		"tools/sourcepolicy/failures_test.go",
		"tools/sourcepolicy/goinspect_dependency_test.go",
		"tools/sourcepolicy/goselection_test.go",
		"tools/sourcepolicy/goskip_timeout_test.go",
		"tools/sourcepolicy/module_replacement_test.go",
		"tools/sourcepolicy/policy_edges_test.go",
	})
	var findings []string
	for _, file := range files {
		if _, denied := obsolete[file]; denied {
			findings = append(findings, splitPathFinding(file, "obsolete split source"))
			continue
		}
		if governedSplitPath(file) {
			if _, declared := allowed[file]; !declared {
				findings = append(findings, splitPathFinding(file, "undeclared split source"))
			}
		}
	}
	return boundedArchitectureFindings(findings)
}

func missingSplitSourceFindings(files []string) []string {
	tracked := stringSet(files)
	var findings []string
	for file := range splitSourceSet() {
		if _, exists := tracked[file]; !exists {
			findings = append(findings, splitPathFinding(file, "required split source is missing"))
		}
	}
	return boundedArchitectureFindings(findings)
}

func splitDirectoryFindings(directories []splitDirectory) []string {
	seen := make(map[string]struct{})
	var findings []string
	for _, directory := range directories {
		for _, file := range directory.files {
			declared := directory.path + "/" + file
			if _, exists := seen[declared]; exists {
				findings = append(findings, splitPathFinding(
					declared, "split source is declared more than once",
				))
			}
			seen[declared] = struct{}{}
		}
	}
	return boundedArchitectureFindings(findings)
}

func splitPathFinding(file, message string) string {
	return fmt.Sprintf("%s: %s", strconv.Quote(file), message)
}

func splitSourceSet() map[string]struct{} {
	files := make(map[string]struct{})
	for _, directory := range splitDirectories() {
		for _, file := range directory.files {
			files[directory.path+"/"+file] = struct{}{}
		}
	}
	return files
}

func governedSplitPath(file string) bool {
	for _, directory := range splitDirectories() {
		if strings.HasPrefix(file, directory.path+"/") {
			if directory.path == "tools/sourcepolicy" {
				return validArchitecturePath(file)
			}
			return true
		}
	}
	return false
}
