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
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestArchitectureRejectsUnsplitSources(t *testing.T) {
	t.Parallel()

	for _, file := range []string{
		"internal/operation/urlreference/transform/urlreference.go",
		"internal/operation/urlreference/protocol/protocol_test.go",
		"worker/url-reference/src/tests.rs",
		"worker/url-reference/src/protocol.rs",
		"worker/url-reference/src/tests/protocol.rs",
	} {
		assertSplitFinding(t, []string{file}, "obsolete split source")
	}
}

func TestArchitectureRequiresSplitDestinations(t *testing.T) {
	t.Parallel()

	files := expectedSplitFiles()
	files = slices.DeleteFunc(files, func(file string) bool {
		return file == "internal/operation/urlreference/transform/host.go"
	})
	findings := missingSplitSourceFindings(files)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, "required split source is missing")
	}) {
		t.Fatalf("findings = %v, want missing destination", findings)
	}
}

func TestArchitectureRejectsUndeclaredSplitSource(t *testing.T) {
	t.Parallel()

	files := append(expectedSplitFiles(),
		"internal/operation/urlreference/protocol/duplicate.go",
	)
	assertSplitFinding(t, files, "undeclared split source")
}

func TestArchitectureSplitDiagnosticsQuotePaths(t *testing.T) {
	t.Parallel()

	file := "internal/operation/urlreference/protocol/hostile\nforged\r\t\x1b\x7f\u0085\u2028\u2029.go"
	findings := splitSourcePathFindings([]string{file})
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one finding", findings)
	}
	if strings.ContainsAny(findings[0], "\n\r\t\x1b\x7f\u0085\u2028\u2029") {
		t.Fatalf("finding contains a raw control character: %q", findings[0])
	}
	if !strings.Contains(findings[0], strconv.Quote(file)) {
		t.Fatalf("finding = %q, want quoted path %q", findings[0], strconv.Quote(file))
	}
}

func TestArchitectureRejectsObsoleteAttemptSource(t *testing.T) {
	t.Parallel()

	assertSplitFinding(t, []string{
		"internal/operation/urlreference/attempt/publication_test.go",
	}, "obsolete split source")
}

func TestArchitectureRequiresAttemptSplitDestination(t *testing.T) {
	t.Parallel()

	files := expectedSplitFiles()
	files = slices.DeleteFunc(files, func(file string) bool {
		return file == "internal/operation/urlreference/attempt/recover.go"
	})
	findings := missingSplitSourceFindings(files)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, "required split source is missing")
	}) {
		t.Fatalf("findings = %v, want missing attempt destination", findings)
	}
}

func TestArchitectureRejectsUndeclaredAttemptSource(t *testing.T) {
	t.Parallel()

	files := append(expectedSplitFiles(),
		"internal/operation/urlreference/attempt/misc.go",
	)
	assertSplitFinding(t, files, "undeclared split source")
}

func TestArchitectureRejectsUnsplitOperation(t *testing.T) {
	t.Parallel()

	assertSplitFinding(t, []string{
		"internal/operation/urlreference/operation_windows_test.go",
	}, "obsolete split source")
}

func TestArchitectureRequiresOperationSplitDestination(t *testing.T) {
	t.Parallel()

	files := expectedSplitFiles()
	files = slices.DeleteFunc(files, func(file string) bool {
		return file == "internal/operation/urlreference/evidence_windows.go"
	})
	findings := missingSplitSourceFindings(files)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, "required split source is missing")
	}) {
		t.Fatalf("findings = %v, want missing operation destination", findings)
	}
}

func TestArchitectureRejectsObsoletePolicySource(t *testing.T) {
	t.Parallel()

	assertSplitFinding(t, []string{
		"tools/sourcepolicy/failures_test.go",
	}, "obsolete split source")
}

func TestArchitectureRequiresPolicyDestination(t *testing.T) {
	t.Parallel()

	files := expectedSplitFiles()
	files = slices.DeleteFunc(files, func(file string) bool {
		return file == "tools/sourcepolicy/architecture_evaluation.go"
	})
	findings := missingSplitSourceFindings(files)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, "required split source is missing")
	}) {
		t.Fatalf("findings = %v, want missing source-policy destination", findings)
	}
}

func TestArchitectureRejectsUndeclaredOperationSource(t *testing.T) {
	t.Parallel()

	files := append(expectedSplitFiles(),
		"internal/operation/urlreference/misc.go",
	)
	assertSplitFinding(t, files, "undeclared split source")
}

func TestArchitectureRejectsUndeclaredPolicySource(t *testing.T) {
	t.Parallel()

	files := append(expectedSplitFiles(), "tools/sourcepolicy/misc.go")
	assertSplitFinding(t, files, "undeclared split source")
}

func TestArchitectureRejectsUndeclaredPolicyArtefacts(t *testing.T) {
	t.Parallel()

	for _, file := range []string{
		"tools/sourcepolicy/rogue.s",
		"tools/sourcepolicy/rogue.rs",
		"tools/sourcepolicy/rogue.json",
		"tools/sourcepolicy/rogue.txt",
		"tools/sourcepolicy/Makefile",
	} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			files := append(expectedSplitFiles(), file)
			assertSplitFinding(t, files, "undeclared split source")
		})
	}
}

func TestArchitectureRejectsMovedPolicyOwner(t *testing.T) {
	t.Parallel()

	files := slices.DeleteFunc(expectedSplitFiles(), func(file string) bool {
		return file == "tools/sourcepolicy/architecture_policy.go"
	})
	files = append(files, "tools/sourcepolicy/architecture_schema.go")
	assertSplitFinding(t, files, "undeclared split source")
	findings := missingSplitSourceFindings(files)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(
			finding,
			strconv.Quote("tools/sourcepolicy/architecture_policy.go")+
				": required split source is missing",
		)
	}) {
		t.Fatalf("findings = %v, want moved owner missing", findings)
	}
}

func TestArchitectureRejectsDuplicateDestination(t *testing.T) {
	t.Parallel()

	directories := []splitDirectory{{
		path:  "tools/sourcepolicy",
		files: []string{"architecture_policy.go", "architecture_policy.go"},
	}}
	findings := splitDirectoryFindings(directories)
	if len(findings) != 1 || !strings.Contains(findings[0], "declared more than once") {
		t.Fatalf("findings = %v, want duplicate destination", findings)
	}
}

func assertSplitFinding(t *testing.T, files []string, fragment string) {
	t.Helper()
	findings := architecturePathFindings(
		files, nil, validArchitectureFixturePolicy(),
	)
	if !slices.ContainsFunc(findings, func(finding string) bool {
		return strings.Contains(finding, fragment)
	}) {
		t.Fatalf("findings = %v, want %q", findings, fragment)
	}
}

func expectedSplitFiles() []string {
	files := []string{
		"internal/operation/urlreference/transform/benchmark_test.go",
		"internal/operation/urlreference/transform/conformance_test.go",
		"internal/operation/urlreference/transform/doc.go",
		"internal/operation/urlreference/transform/hex_test.go",
		"internal/operation/urlreference/transform/host.go",
		"internal/operation/urlreference/transform/parse.go",
		"internal/operation/urlreference/transform/text.go",
		"internal/operation/urlreference/transform/transform.go",
		"internal/operation/urlreference/transform/urlreference_test.go",
		"internal/operation/urlreference/protocol/benchmark_test.go",
		"internal/operation/urlreference/protocol/doc.go",
		"internal/operation/urlreference/protocol/frame.go",
		"internal/operation/urlreference/protocol/frame_test.go",
		"internal/operation/urlreference/protocol/fuzz_test.go",
		"internal/operation/urlreference/protocol/protocol.go",
		"internal/operation/urlreference/protocol/request.go",
		"internal/operation/urlreference/protocol/request_test.go",
		"internal/operation/urlreference/protocol/response.go",
		"internal/operation/urlreference/protocol/response_test.go",
		"internal/operation/urlreference/admission/admission.go",
		"internal/operation/urlreference/admission/admission_test.go",
		"internal/operation/urlreference/admission/doc.go",
		"worker/url-reference/src/grammar.rs",
		"worker/url-reference/src/main.rs",
		"worker/url-reference/src/request.rs",
		"worker/url-reference/src/response.rs",
		"worker/url-reference/src/tests/grammar.rs",
		"worker/url-reference/src/tests/mod.rs",
		"worker/url-reference/src/tests/request.rs",
		"worker/url-reference/src/tests/response.rs",
		"worker/url-reference/src/tests/transform.rs",
		"worker/url-reference/src/transform.rs",
	}
	files = append(files, expectedAttemptSplitFiles()...)
	files = append(files, expectedOperationSplitFiles()...)
	for _, file := range sourcePolicySplitFiles() {
		files = append(files, "tools/sourcepolicy/"+file)
	}
	for _, file := range actionPolicySplitFiles() {
		files = append(files, "tools/actionpolicy/"+file)
	}
	return files
}

func expectedOperationSplitFiles() []string {
	return []string{
		"internal/operation/urlreference/admission_windows_test.go",
		"internal/operation/urlreference/benchmark_windows_test.go",
		"internal/operation/urlreference/cancellation_windows_test.go",
		"internal/operation/urlreference/diagnostics_windows_test.go",
		"internal/operation/urlreference/doc.go",
		"internal/operation/urlreference/evidence_windows.go",
		"internal/operation/urlreference/execution_windows_test.go",
		"internal/operation/urlreference/operation.go",
		"internal/operation/urlreference/operation_unsupported.go",
		"internal/operation/urlreference/operation_unsupported_test.go",
		"internal/operation/urlreference/operation_windows.go",
		"internal/operation/urlreference/platform_windows.go",
		"internal/operation/urlreference/projection_windows.go",
		"internal/operation/urlreference/protocol_windows_test.go",
		"internal/operation/urlreference/publication_windows_test.go",
		"internal/operation/urlreference/test_support_windows_test.go",
		"internal/operation/urlreference/verification_windows.go",
		"internal/operation/urlreference/verification_windows_test.go",
	}
}

func expectedAttemptSplitFiles() []string {
	return []string{
		"internal/operation/urlreference/attempt/acl_fault_windows_test.go",
		"internal/operation/urlreference/attempt/acl_windows.go",
		"internal/operation/urlreference/attempt/acl_windows_test.go",
		"internal/operation/urlreference/attempt/admitted_binding_test.go",
		"internal/operation/urlreference/attempt/contract.go",
		"internal/operation/urlreference/attempt/decision_invariants_test.go",
		"internal/operation/urlreference/attempt/doc.go",
		"internal/operation/urlreference/attempt/fail_closed_test.go",
		"internal/operation/urlreference/attempt/identity_test.go",
		"internal/operation/urlreference/attempt/inspect.go",
		"internal/operation/urlreference/attempt/inspect_integrity_test.go",
		"internal/operation/urlreference/attempt/inspect_test.go",
		"internal/operation/urlreference/attempt/inspection_concurrency_test.go",
		"internal/operation/urlreference/attempt/lock.go",
		"internal/operation/urlreference/attempt/lock_fail_closed_test.go",
		"internal/operation/urlreference/attempt/lock_fault_injection_windows_test.go",
		"internal/operation/urlreference/attempt/lock_root.go",
		"internal/operation/urlreference/attempt/lock_root_test.go",
		"internal/operation/urlreference/attempt/lock_test.go",
		"internal/operation/urlreference/attempt/lock_windows.go",
		"internal/operation/urlreference/attempt/lock_windows_test.go",
		"internal/operation/urlreference/attempt/observation_validation.go",
		"internal/operation/urlreference/attempt/observation_validation_test.go",
		"internal/operation/urlreference/attempt/ownership.go",
		"internal/operation/urlreference/attempt/ownership_test.go",
		"internal/operation/urlreference/attempt/paths.go",
		"internal/operation/urlreference/attempt/paths_fault_test.go",
		"internal/operation/urlreference/attempt/platform.go",
		"internal/operation/urlreference/attempt/publish.go",
		"internal/operation/urlreference/attempt/publish_fault_windows_test.go",
		"internal/operation/urlreference/attempt/publish_result_test.go",
		"internal/operation/urlreference/attempt/publish_test.go",
		"internal/operation/urlreference/attempt/publish_windows.go",
		"internal/operation/urlreference/attempt/publish_windows_test.go",
		"internal/operation/urlreference/attempt/record.go",
		"internal/operation/urlreference/attempt/record_fault_windows_test.go",
		"internal/operation/urlreference/attempt/record_fuzz_test.go",
		"internal/operation/urlreference/attempt/record_io.go",
		"internal/operation/urlreference/attempt/record_io_test.go",
		"internal/operation/urlreference/attempt/record_name.go",
		"internal/operation/urlreference/attempt/record_name_test.go",
		"internal/operation/urlreference/attempt/record_recovery_windows_test.go",
		"internal/operation/urlreference/attempt/record_validation.go",
		"internal/operation/urlreference/attempt/record_validation_test.go",
		"internal/operation/urlreference/attempt/record_windows.go",
		"internal/operation/urlreference/attempt/recover.go",
		"internal/operation/urlreference/attempt/recovery_cleanup_test.go",
		"internal/operation/urlreference/attempt/recovery_fault_test.go",
		"internal/operation/urlreference/attempt/recovery_interruption_windows_test.go",
		"internal/operation/urlreference/attempt/recovery_test.go",
		"internal/operation/urlreference/attempt/repair_fault_windows_test.go",
		"internal/operation/urlreference/attempt/repair_windows.go",
		"internal/operation/urlreference/attempt/request_v1.go",
		"internal/operation/urlreference/attempt/request_v1_test.go",
		"internal/operation/urlreference/attempt/root.go",
		"internal/operation/urlreference/attempt/root_fault_test.go",
		"internal/operation/urlreference/attempt/root_parent_windows.go",
		"internal/operation/urlreference/attempt/root_path_windows.go",
		"internal/operation/urlreference/attempt/root_path_windows_test.go",
		"internal/operation/urlreference/attempt/stage.go",
		"internal/operation/urlreference/attempt/staging_fault_windows_test.go",
		"internal/operation/urlreference/attempt/staging_test.go",
		"internal/operation/urlreference/attempt/store.go",
		"internal/operation/urlreference/attempt/store_fault_test.go",
		"internal/operation/urlreference/attempt/store_test.go",
		"internal/operation/urlreference/attempt/store_unsupported.go",
		"internal/operation/urlreference/attempt/store_unsupported_test.go",
		"internal/operation/urlreference/attempt/terminal.go",
		"internal/operation/urlreference/attempt/terminal_fault_test.go",
		"internal/operation/urlreference/attempt/transition.go",
		"internal/operation/urlreference/attempt/transition_test.go",
	}
}
