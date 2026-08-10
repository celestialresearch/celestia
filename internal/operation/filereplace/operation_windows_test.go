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

//go:build windows && amd64

package filereplace

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"celestia.research/celestia/internal/operation/filereplace/admission"
	"celestia.research/celestia/internal/operation/filereplace/attempt"
	"golang.org/x/sys/windows"
)

const deathStageEnvironment = "CELESTIA_FILE_REPLACE_DEATH_STAGE"

func TestOperationReplacesAndVerifies(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.State != attempt.StateVerified || !result.CleanupComplete {
		t.Fatalf("Execute() result = %+v", result)
	}
	inspected, err := operation.Inspect(result.AttemptID)
	if err != nil || inspected != result {
		t.Fatalf("Inspect() = %+v, %v", inspected, err)
	}
	data, err := readTestTarget(operation)
	if err != nil || string(data) != "after" {
		t.Fatalf("target = %q, %v", data, err)
	}
}

func TestOperationRejectsChangedPrecondition(t *testing.T) {
	operation := newTestOperation(t, []byte("changed"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrPrecondition) || result.State != attempt.StateFailed {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	data, readErr := readTestTarget(operation)
	if readErr != nil || string(data) != "changed" {
		t.Fatalf("target = %q, %v", data, readErr)
	}
}

func TestOperationCancelsBeforeCommit(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := operation.Execute(ctx, request)
	if !errors.Is(err, context.Canceled) || result.State != attempt.StateCancelled {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	data, readErr := readTestTarget(operation)
	if readErr != nil || string(data) != "before" {
		t.Fatalf("target = %q, %v", data, readErr)
	}
}

func TestOperationRejectsHardLinkedTarget(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	target := filepath.Join(operation.platform.targetPath, "target.txt")
	link := filepath.Join(filepath.Dir(target), "link.txt")
	if err := os.Link(target, link); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrTarget) || result.State != attempt.StateFailed {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestOperationRejectsReplacedTargetAtFinalBoundary(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	operation.platform.faults.beforeFinalCheck = func() {
		if err := operation.platform.target.Remove("target.txt"); err != nil {
			t.Fatal(err)
		}
		if err := writeTarget(operation, []byte("substitute")); err != nil {
			t.Fatal(err)
		}
	}
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrPrecondition) || result.State != attempt.StateFailed {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestOperationPreventsRootPathReplacement(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	original := operation.platform.targetPath
	moved := original + "-moved"
	if err := os.Rename(original, moved); err == nil {
		t.Fatal("Rename() unexpectedly replaced an active root path")
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if err != nil || result.State != attempt.StateVerified {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	data, err := readTestTarget(operation)
	if err != nil || string(data) != "after" {
		t.Fatalf("target = %q, %v", data, err)
	}
}

func TestOperationIgnoresCancellationAfterCommit(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	ctx, cancel := context.WithCancel(context.Background())
	operation.platform.faults.afterCommit = cancel
	result, err := operation.Execute(ctx, request)
	if err != nil || result.State != attempt.StateVerified {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestOperationCloseIsIdempotent(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	if err := operation.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	if _, err := operation.Execute(context.Background(), request); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Execute() after Close error = %v", err)
	}
	if _, err := operation.Recover(context.Background()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Recover() after Close error = %v", err)
	}
	if _, err := operation.Inspect(strings.Repeat("a", 43)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Inspect() after Close error = %v", err)
	}
}

func TestOperationRecoversDurableRecordFailures(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*operationFaults)
	}{
		{"directory sync", func(faults *operationFaults) { faults.targetSync = errors.New("sync") }},
		{"effect record", func(faults *operationFaults) { faults.effectRecord = errors.New("effect") }},
		{"verification record", func(faults *operationFaults) { faults.verification = errors.New("verify") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := newTestOperation(t, []byte("before"))
			test.apply(&operation.platform.faults)
			request := admitTestRequest(t, []byte("before"), []byte("after"))
			result, err := operation.Execute(context.Background(), request)
			if !errors.Is(err, ErrIndeterminate) || result.State != attempt.StateIndeterminate {
				t.Fatalf("Execute() = %+v, %v", result, err)
			}
			operation.platform.faults = operationFaults{}
			results, recoverErr := operation.Recover(context.Background())
			if recoverErr != nil || len(results) != 1 || results[0].State != attempt.StateVerified {
				t.Fatalf("Recover() = %+v, %v", results, recoverErr)
			}
		})
	}
}

func TestOperationRecordsCleanupFailureSeparately(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	cleanupErr := errors.New("cleanup")
	operation.platform.faults.cleanup = cleanupErr
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, cleanupErr) || result.State != attempt.StateVerified || result.CleanupComplete {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	inspected, inspectErr := operation.Inspect(result.AttemptID)
	if inspectErr != nil || inspected != result {
		t.Fatalf("Inspect() = %+v, %v", inspected, inspectErr)
	}
}

func TestOperationReportsTemporaryCleanupFailure(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	var handle windows.Handle
	var temporary string
	operation.platform.faults.beforeFinalCheck = func() {
		handle, temporary = lockTemporaryAndChangeTarget(t, operation)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrPrecondition) || result.State != attempt.StateFailed ||
		result.CleanupComplete {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	if closeErr := windows.CloseHandle(handle); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err := operation.platform.target.Remove(temporary); err != nil {
		t.Fatal(err)
	}
}

func lockTemporaryAndChangeTarget(
	t *testing.T,
	operation *Operation,
) (windows.Handle, string) {
	t.Helper()
	entries, err := os.ReadDir(operation.platform.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	var temporary string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".celestia-") {
			temporary = entry.Name()
		}
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Join(operation.platform.targetPath, temporary))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.platform.target.Remove("target.txt"); err != nil {
		t.Fatal(err)
	}
	if err := writeTarget(operation, []byte("changed")); err != nil {
		t.Fatal(err)
	}
	return handle, temporary
}

func TestOperationCleansPartialPreparation(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	operation.platform.faults.partialWrite = true
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, io.ErrShortWrite) || result.State != attempt.StateFailed {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	data, readErr := readTestTarget(operation)
	if readErr != nil || string(data) != "before" {
		t.Fatalf("target = %q, %v", data, readErr)
	}
}

func TestOperationPreservesNativeRenameFailure(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	target, err := windows.UTF16PtrFromString(filepath.Join(operation.platform.targetPath, "target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		target, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("CloseHandle() error = %v", err)
		}
	}()
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if err == nil || result.State != attempt.StateFailed {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	assertNoTemporary(t, operation)
}

func assertNoTemporary(t *testing.T, operation *Operation) {
	t.Helper()
	entries, err := os.ReadDir(operation.platform.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".celestia-") {
			t.Fatalf("temporary file retained: %s", entry.Name())
		}
	}
}

func TestOperationCleansTemporaryWhenRenameEvidenceFails(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	operation.platform.faults.effectRecord = errors.New("effect record")
	target, err := windows.UTF16PtrFromString(filepath.Join(operation.platform.targetPath, "target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		target, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("CloseHandle() error = %v", err)
		}
	}()
	result, err := operation.Execute(
		context.Background(), admitTestRequest(t, []byte("before"), []byte("after")),
	)
	if !errors.Is(err, ErrIndeterminate) || result.State != attempt.StateIndeterminate ||
		!result.CleanupComplete {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	assertNoTemporary(t, operation)
}

func TestOperationRejectsPostconditionSubstitution(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	operation.platform.faults.afterCommit = func() {
		if err := operation.platform.target.Remove("target.txt"); err != nil {
			t.Fatal(err)
		}
		if err := writeTarget(operation, []byte("substitute")); err != nil {
			t.Fatal(err)
		}
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrIndeterminate) || result.State != attempt.StateIndeterminate {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestOperationPreservesUnavailablePostcondition(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	operation.platform.faults.afterCommit = func() {
		if err := operation.platform.target.Remove("target.txt"); err != nil {
			t.Fatal(err)
		}
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrIndeterminate) || result.State != attempt.StateIndeterminate {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestOperationRejectsConcurrentExecution(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	journal := beginInterruptedAttempt(
		t, operation, admitTestRequest(t, []byte("before"), []byte("pending")),
	)
	defer func() {
		if err := journal.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, attempt.ErrLockHeld) || result != (Result{}) {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestInspectFailedAttemptHasNoObservedDigest(t *testing.T) {
	operation := newTestOperation(t, []byte("changed"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrPrecondition) {
		t.Fatal(err)
	}
	inspected, err := operation.Inspect(result.AttemptID)
	if err != nil || inspected.ObservedSHA256 != ([32]byte{}) || inspected.State != attempt.StateFailed {
		t.Fatalf("Inspect() = %+v, %v", inspected, err)
	}
}

func TestOperationRecoversPublicationFailure(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	publicationErr := errors.New("publication")
	operation.platform.faults.publication = publicationErr
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, publicationErr) || !errors.Is(err, ErrIndeterminate) ||
		result.State != attempt.StateIndeterminate {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
	operation.platform.faults = operationFaults{}
	results, recoverErr := operation.Recover(context.Background())
	if recoverErr != nil || len(results) != 1 || results[0].State != attempt.StateVerified {
		t.Fatalf("Recover() = %+v, %v", results, recoverErr)
	}
}

func TestNewRejectsSameRoot(t *testing.T) {
	root := secureTestDirectory(t, filepath.Join(t.TempDir(), "root"))
	if _, err := New(Config{TargetRoot: root, EvidenceRoot: root}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New() error = %v", err)
	}
}

func TestOperationAPIsRejectNilReceiver(t *testing.T) {
	var operation *Operation
	if _, err := operation.Execute(context.Background(), admission.Request{}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Execute() error = %v", err)
	}
	if _, err := operation.Recover(context.Background()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := operation.Inspect("invalid"); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("Inspect() error = %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewRejectsUnsafeRoots(t *testing.T) {
	base := t.TempDir()
	unsafeRoot := filepath.Join(base, "unsafe")
	if err := os.Mkdir(unsafeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	secureRoot := secureTestDirectory(t, filepath.Join(base, "secure"))
	for _, config := range []Config{
		{TargetRoot: unsafeRoot, EvidenceRoot: secureRoot},
		{TargetRoot: secureRoot, EvidenceRoot: unsafeRoot},
	} {
		if operation, err := New(config); !errors.Is(err, ErrConfiguration) || operation != nil {
			t.Fatalf("New() = %+v, %v", operation, err)
		}
	}
}

func TestOperationRejectsUnsafeTargetForms(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*Operation) error
	}{
		{"missing", func(operation *Operation) error {
			return operation.platform.target.Remove("target.txt")
		}},
		{"directory", func(operation *Operation) error {
			if err := operation.platform.target.Remove("target.txt"); err != nil {
				return err
			}
			return operation.platform.target.Mkdir("target.txt", 0o700)
		}},
		{"oversized", func(operation *Operation) error {
			file, err := operation.platform.target.OpenFile("target.txt", os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				return err
			}
			_, writeErr := file.Write(make([]byte, admission.MaxReplacementBytes+1))
			return errors.Join(writeErr, file.Close())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := newTestOperation(t, []byte("before"))
			if err := test.setup(operation); err != nil {
				t.Fatal(err)
			}
			request := admitTestRequest(t, []byte("before"), []byte("after"))
			result, err := operation.Execute(context.Background(), request)
			if err == nil || result.State != attempt.StateFailed {
				t.Fatalf("Execute() = %+v, %v", result, err)
			}
		})
	}
}

func TestOperationRejectsInvalidInspectionAndRecoveryCancellation(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	if _, err := operation.Inspect("invalid"); !errors.Is(err, attempt.ErrCorrupt) {
		t.Fatalf("Inspect() error = %v", err)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := operation.Recover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recover() error = %v", err)
	}
	if _, err := decodeSHA256("invalid"); !errors.Is(err, attempt.ErrCorrupt) {
		t.Fatalf("decodeSHA256() error = %v", err)
	}
}

func TestOperationRejectsPermissiveTarget(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	target := filepath.Join(operation.platform.targetPath, "target.txt")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FR;;;WD)", user.User.Sid, user.User.Sid),
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		target, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatal(err)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	result, err := operation.Execute(context.Background(), request)
	if !errors.Is(err, ErrTarget) || result.State != attempt.StateFailed {
		t.Fatalf("Execute() = %+v, %v", result, err)
	}
}

func TestAllowedACESIDRejectsTruncatedSID(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	ace := windows.ACCESS_ALLOWED_ACE{}
	ace.Header.AceSize = uint16(unsafe.Offsetof(ace.SidStart) + 8)
	ace.SidStart = 1 | 1<<8
	if allowedACESID(&ace, user.User.Sid) {
		t.Fatal("allowedACESID() accepted a SID extending beyond its ACE")
	}
}

func TestTargetSecurityHelpersRejectInvalidValues(t *testing.T) {
	if ownedProtectedTargetRoot(nil) || exclusiveTargetDACL(nil, nil) ||
		ownedExclusiveTarget(nil) {
		t.Fatal("target security helper accepted invalid state")
	}
	if err := syncTargetDirectory(nil); !errors.Is(err, ErrTarget) {
		t.Fatalf("syncTargetDirectory() error = %v", err)
	}
	if validFixedTargetRoot("relative", "relative") {
		t.Fatal("validFixedTargetRoot() accepted a relative path")
	}
}

func TestTargetDACLRejectsWrongAccess(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FR;;;%s)", user.User.Sid, user.User.Sid),
	)
	if err != nil {
		t.Fatal(err)
	}
	if ownedProtectedTargetRoot(descriptor) {
		t.Fatal("ownedProtectedTargetRoot() accepted read-only target access")
	}
}

func TestTargetInformationRejectsUnsafeFiles(t *testing.T) {
	tests := []windows.ByHandleFileInformation{
		{NumberOfLinks: 2},
		{NumberOfLinks: 1, FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY},
		{NumberOfLinks: 1, FileAttributes: windows.FILE_ATTRIBUTE_REPARSE_POINT},
	}
	for _, information := range tests {
		if validTargetFileInformation(information) {
			t.Fatalf("validTargetFileInformation(%+v) accepted unsafe file", information)
		}
	}
	if !validTargetFileInformation(windows.ByHandleFileInformation{NumberOfLinks: 1}) {
		t.Fatal("validTargetFileInformation() rejected an ordinary file")
	}
}

func TestRecoveryRemovesUncommittedPreparation(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	if err := operation.platform.prepare(journal.Intent().Temporary, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	results, err := operation.Recover(context.Background())
	if err != nil || len(results) != 1 || results[0].State != attempt.StateFailed {
		t.Fatalf("Recover() = %+v, %v", results, err)
	}
	data, readErr := readTestTarget(operation)
	if readErr != nil || string(data) != "before" {
		t.Fatalf("target = %q, %v", data, readErr)
	}
}

func TestRecoveryRecordsTemporarySyncFailure(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	if err := operation.platform.prepare(journal.Intent().Temporary, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	operation.platform.faults.targetSync = errors.New("target sync")
	results, err := operation.Recover(context.Background())
	if err == nil || len(results) != 1 || results[0].State != attempt.StateFailed ||
		results[0].CleanupComplete {
		t.Fatalf("Recover() = %+v, %v", results, err)
	}
}

func TestRecoveryVerifiesCommittedTargetWithoutRepeatingEffect(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	temporary := journal.Intent().Temporary
	if err := operation.platform.prepare(temporary, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkCommit(); err != nil {
		t.Fatal(err)
	}
	if err := operation.platform.target.Rename(temporary, "target.txt"); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	results, err := operation.Recover(context.Background())
	if err != nil || len(results) != 1 || results[0].State != attempt.StateVerified {
		t.Fatalf("Recover() = %+v, %v", results, err)
	}
	data, readErr := readTestTarget(operation)
	if readErr != nil || string(data) != "after" {
		t.Fatalf("target = %q, %v", data, readErr)
	}
}

func TestRecoveryPreservesUncertainCommit(t *testing.T) {
	operation := newTestOperation(t, []byte("before"))
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	if err := operation.platform.prepare(journal.Intent().Temporary, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkCommit(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	results, err := operation.Recover(context.Background())
	if !errors.Is(err, ErrIndeterminate) || len(results) != 1 ||
		results[0].State != attempt.StateIndeterminate {
		t.Fatalf("Recover() = %+v, %v", results, err)
	}
}

func TestRecoveryRejectsDifferentTargetRoot(t *testing.T) {
	firstRoot, secondRoot, evidenceRoot := recoveryRootPair(t)
	first, err := New(Config{TargetRoot: firstRoot, EvidenceRoot: evidenceRoot})
	if err != nil {
		t.Fatal(err)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, first, request)
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{TargetRoot: secondRoot, EvidenceRoot: evidenceRoot})
	if err != nil {
		t.Fatal(err)
	}
	cleanupOperation(t, second)
	if _, err := second.Recover(context.Background()); !errors.Is(err, ErrConfiguration) || !errors.Is(err, attempt.ErrCorrupt) {
		t.Fatalf("Recover() error = %v", err)
	}
	data, err := readTestTarget(second)
	if err != nil || string(data) != "before" {
		t.Fatalf("second target = %q, %v", data, err)
	}
}

func recoveryRootPair(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	first := secureTestDirectory(t, filepath.Join(base, "first"))
	second := secureTestDirectory(t, filepath.Join(base, "second"))
	evidence := secureTestDirectory(t, filepath.Join(base, "evidence"))
	for _, root := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return first, second, evidence
}

func TestRecoveryAfterProcessDeath(t *testing.T) {
	for _, test := range []struct {
		stage  string
		state  attempt.State
		target string
	}{
		{"intent", attempt.StateFailed, "before"},
		{"prepared", attempt.StateFailed, "before"},
		{"commit", attempt.StateIndeterminate, "before"},
		{"renamed", attempt.StateVerified, "after"},
		{"effect", attempt.StateVerified, "after"},
		{"verification", attempt.StateVerified, "after"},
	} {
		t.Run(test.stage, func(t *testing.T) {
			runDeathCase(t, test.stage, test.state, test.target)
		})
	}
}

func TestOperationRequiresRecoveryAfterOwnerDeath(t *testing.T) {
	for _, replacement := range [][]byte{[]byte("after"), []byte("different")} {
		t.Run(string(replacement), func(t *testing.T) {
			targetRoot, evidenceRoot := deathTestRoots(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			// #nosec G204,G702 -- os.Args[0] is the current Go test binary.
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileReplaceDeathHelper$")
			command.Env = append(os.Environ(),
				deathStageEnvironment+"=commit",
				"CELESTIA_FILE_REPLACE_TARGET_ROOT="+targetRoot,
				"CELESTIA_FILE_REPLACE_EVIDENCE_ROOT="+evidenceRoot,
			)
			waitForDeathCheckpoint(t, command)
			operation, err := New(Config{TargetRoot: targetRoot, EvidenceRoot: evidenceRoot})
			if err != nil {
				t.Fatal(err)
			}
			cleanupOperation(t, operation)
			request := admitTestRequest(t, []byte("before"), replacement)
			if _, err := operation.Execute(context.Background(), request); !errors.Is(err, attempt.ErrRecoveryRequired) {
				t.Fatalf("Execute() error = %v", err)
			}
		})
	}
}

func TestRecoveryVerificationSurvivesProcessDeath(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name := "unchanged"
		if changed {
			name = "changed"
		}
		t.Run(name, func(t *testing.T) { runRecoveryVerificationDeath(t, changed) })
	}
}

func runRecoveryVerificationDeath(t *testing.T, changed bool) {
	t.Helper()
	targetRoot, evidenceRoot := deathTestRoots(t)
	stageCommittedAttempt(t, targetRoot, evidenceRoot)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// #nosec G204,G702 -- os.Args[0] is the current Go test binary.
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileReplaceDeathHelper$")
	command.Env = append(os.Environ(),
		deathStageEnvironment+"=recovery-verification",
		"CELESTIA_FILE_REPLACE_TARGET_ROOT="+targetRoot,
		"CELESTIA_FILE_REPLACE_EVIDENCE_ROOT="+evidenceRoot,
	)
	waitForDeathCheckpoint(t, command)
	if changed {
		if err := os.WriteFile(filepath.Join(targetRoot, "target.txt"), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	operation, err := New(Config{TargetRoot: targetRoot, EvidenceRoot: evidenceRoot})
	if err != nil {
		t.Fatal(err)
	}
	cleanupOperation(t, operation)
	results, recoverErr := operation.Recover(context.Background())
	if !changed {
		if recoverErr != nil || len(results) != 1 || results[0].State != attempt.StateVerified {
			t.Fatalf("Recover() = %+v, %v", results, recoverErr)
		}
		return
	}
	if !errors.Is(recoverErr, ErrIndeterminate) || !errors.Is(recoverErr, attempt.ErrDuplicate) ||
		len(results) != 1 || results[0].State != attempt.StateIndeterminate {
		t.Fatalf("Recover() = %+v, %v", results, recoverErr)
	}
}

func cleanupOperation(t *testing.T, operation *Operation) {
	t.Helper()
	t.Cleanup(func() {
		if err := operation.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
}

func stageCommittedAttempt(t *testing.T, targetRoot, evidenceRoot string) {
	t.Helper()
	operation, err := New(Config{TargetRoot: targetRoot, EvidenceRoot: evidenceRoot})
	if err != nil {
		t.Fatal(err)
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	if err := operation.platform.prepare(journal.Intent().Temporary, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkCommit(); err != nil {
		t.Fatal(err)
	}
	if err := operation.platform.target.Rename(journal.Intent().Temporary, "target.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecordEffect(true); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := operation.Close(); err != nil {
		t.Fatal(err)
	}
}

func runDeathCase(t *testing.T, stage string, wantState attempt.State, wantTarget string) {
	t.Helper()
	targetRoot, evidenceRoot := deathTestRoots(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// #nosec G204,G702 -- os.Args[0] is the current Go test binary.
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileReplaceDeathHelper$")
	command.Env = append(os.Environ(),
		deathStageEnvironment+"="+stage,
		"CELESTIA_FILE_REPLACE_TARGET_ROOT="+targetRoot,
		"CELESTIA_FILE_REPLACE_EVIDENCE_ROOT="+evidenceRoot,
	)
	waitForDeathCheckpoint(t, command)
	operation, err := New(Config{TargetRoot: targetRoot, EvidenceRoot: evidenceRoot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := operation.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	results, recoverErr := operation.Recover(context.Background())
	if wantState == attempt.StateIndeterminate && !errors.Is(recoverErr, ErrIndeterminate) {
		t.Fatalf("Recover() error = %v", recoverErr)
	}
	if wantState != attempt.StateIndeterminate && recoverErr != nil {
		t.Fatalf("Recover() error = %v", recoverErr)
	}
	if len(results) != 1 || results[0].State != wantState {
		t.Fatalf("Recover() = %+v", results)
	}
	data, err := readTestTarget(operation)
	if err != nil || string(data) != wantTarget {
		t.Fatalf("target = %q, %v", data, err)
	}
}

func waitForDeathCheckpoint(t *testing.T, command *exec.Cmd) {
	t.Helper()
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	diagnostics := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(stderr, 64<<10+1))
		diagnostics <- data
	}()
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && line != "ready\n" {
			readErr = fmt.Errorf("helper output %q", line)
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		if err != nil {
			terminateDeathHelper(t, command, waited, diagnostics,
				fmt.Sprintf("checkpoint failed: %v", err))
		}
	case err := <-waited:
		t.Fatalf("death helper exited before checkpoint: %v; stderr=%q",
			err, awaitDeathDiagnostics(t, diagnostics))
	case <-time.After(10 * time.Second):
		terminateDeathHelper(t, command, waited, diagnostics, "checkpoint timeout")
	}
	if err := command.Process.Kill(); err != nil {
		select {
		case waitErr := <-waited:
			t.Fatalf("death helper exited before termination: %v; kill=%v; stderr=%q",
				waitErr, err, <-diagnostics)
		default:
			t.Fatalf("terminate death helper: %v", err)
		}
	}
	if err := awaitDeathWait(t, waited); err == nil {
		t.Fatal("killed helper exited successfully")
	}
	if data := awaitDeathDiagnostics(t, diagnostics); len(data) != 0 {
		t.Fatalf("killed helper wrote stderr: %q", data)
	}
}

func terminateDeathHelper(
	t *testing.T,
	command *exec.Cmd,
	waited <-chan error,
	diagnostics <-chan []byte,
	reason string,
) {
	t.Helper()
	killErr := command.Process.Kill()
	waitErr := awaitDeathWait(t, waited)
	t.Fatalf("death helper %s: kill=%v wait=%v stderr=%q",
		reason, killErr, waitErr, awaitDeathDiagnostics(t, diagnostics))
}

func awaitDeathWait(t *testing.T, waited <-chan error) error {
	t.Helper()
	select {
	case err := <-waited:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("death helper wait timed out")
		return nil
	}
}

func awaitDeathDiagnostics(t *testing.T, diagnostics <-chan []byte) []byte {
	t.Helper()
	select {
	case data := <-diagnostics:
		return data
	case <-time.After(10 * time.Second):
		t.Fatal("death helper diagnostics timed out")
		return nil
	}
}

func TestFileReplaceDeathHelper(t *testing.T) {
	stage := os.Getenv(deathStageEnvironment)
	if stage == "" {
		return
	}
	operation, err := New(Config{
		TargetRoot:   os.Getenv("CELESTIA_FILE_REPLACE_TARGET_ROOT"),
		EvidenceRoot: os.Getenv("CELESTIA_FILE_REPLACE_EVIDENCE_ROOT"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stage == "recovery-verification" {
		operation.platform.faults.afterRecoveryVerification = func() {
			if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
				t.Fatal(err)
			}
			waitForDeathParent(t)
		}
		if _, err := operation.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Fatal("Recover() returned before the death checkpoint")
	}
	request := admitTestRequest(t, []byte("before"), []byte("after"))
	journal := beginInterruptedAttempt(t, operation, request)
	advanceDeathHelper(t, operation, journal, stage)
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	waitForDeathParent(t)
}

func waitForDeathParent(t *testing.T) {
	t.Helper()
	var data [1]byte
	if _, err := os.Stdin.Read(data[:]); err != nil {
		t.Fatalf("death helper parent boundary closed: %v", err)
	}
	t.Fatal("death helper received unexpected parent data")
}

func advanceDeathHelper(
	t *testing.T,
	operation *Operation,
	journal *attempt.Attempt,
	stage string,
) {
	t.Helper()
	if stage == "intent" {
		return
	}
	if err := operation.platform.prepare(journal.Intent().Temporary, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if stage == "prepared" {
		return
	}
	if err := journal.MarkCommit(); err != nil {
		t.Fatal(err)
	}
	if stage == "commit" {
		return
	}
	if err := operation.platform.target.Rename(journal.Intent().Temporary, "target.txt"); err != nil {
		t.Fatal(err)
	}
	if stage == "renamed" {
		return
	}
	if _, err := journal.RecordEffect(true); err != nil {
		t.Fatal(err)
	}
	if stage == "effect" {
		return
	}
	digest := sha256.Sum256([]byte("after"))
	if _, err := journal.RecordVerification(attempt.Verification{
		Observed: true, ObservedSHA256: hex.EncodeToString(digest[:]),
		ObservedLength: 5, Matched: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func deathTestRoots(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	targetRoot := secureTestDirectory(t, filepath.Join(base, "target"))
	evidenceRoot := secureTestDirectory(t, filepath.Join(base, "evidence"))
	if err := os.WriteFile(filepath.Join(targetRoot, "target.txt"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	return targetRoot, evidenceRoot
}

func newTestOperation(t *testing.T, content []byte) *Operation {
	t.Helper()

	base := t.TempDir()
	targetRoot := secureTestDirectory(t, filepath.Join(base, "target"))
	evidenceRoot := secureTestDirectory(t, filepath.Join(base, "evidence"))
	target := filepath.Join(targetRoot, "target.txt")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	operation, err := New(Config{TargetRoot: targetRoot, EvidenceRoot: evidenceRoot})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := operation.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return operation
}

func secureTestDirectory(t *testing.T, path string) string {
	t.Helper()

	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)", user.User.Sid, user.User.Sid),
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatal(err)
	}
	return path
}

func admitTestRequest(t *testing.T, before, after []byte) admission.Request {
	t.Helper()

	digest := sha256.Sum256(before)
	request, err := admission.Admit(admission.Input{
		Target: "target.txt", ExpectedSHA256: hex.EncodeToString(digest[:]), Replacement: after,
	})
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	return request
}

func readTestTarget(operation *Operation) ([]byte, error) {
	file, err := operation.platform.target.Open("target.txt")
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(file)
	return data, errors.Join(readErr, file.Close())
}

func writeTarget(operation *Operation, content []byte) error {
	file, err := operation.platform.target.OpenFile(
		"target.txt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	return errors.Join(writeErr, file.Close())
}

func beginInterruptedAttempt(
	t *testing.T,
	operation *Operation,
	request admission.Request,
) *attempt.Attempt {
	t.Helper()

	replacement := request.Replacement()
	replacementHash := sha256.Sum256(replacement)
	expected := request.ExpectedSHA256()
	journal, err := operation.platform.store.Begin(attempt.BeginData{
		TargetRoot: operation.platform.targetID,
		Target:     request.Target(), ExpectedSHA256: hex.EncodeToString(expected[:]),
		ReplacementSHA256: hex.EncodeToString(replacementHash[:]),
		ReplacementLength: int64(len(replacement)),
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	return journal
}
