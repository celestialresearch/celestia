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

package attempt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const recordDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var testRootIdentity = RootIdentity{
	VolumeSerial: 1,
	FileID:       "0123456789abcdef0123456789abcdef",
}

func TestStoreWritesAppendOnlyJournal(t *testing.T) {
	store := newTestStore(t)
	journal := publishTestAttempt(t, store)
	for _, suffix := range []string{
		"intent", "prepared", "commit", "effect", "verification", "receipt",
	} {
		path := filepath.Join(store.path, journal.intent.AttemptID+"."+suffix+".json")
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("record %s missing: %v", suffix, err)
		}
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatalf("idempotent checkpoint error = %v", err)
	}
}

func TestRecordPublicationRecoversEveryCheckpointFailure(t *testing.T) {
	failure := errors.New("injected record failure")
	for _, test := range []struct {
		name  string
		fault recordFaults
	}{
		{"write", recordFaults{write: failure}},
		{"short write", recordFaults{shortWrite: true}},
		{"sync", recordFaults{sync: failure}},
		{"close", recordFaults{close: failure}},
		{"publish", recordFaults{publish: failure}},
		{"directory sync", recordFaults{directorySync: failure}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			data := []byte("{\"record\":true}\n")
			store.faults = test.fault
			if err := store.writeRecord("record.json", data); err == nil {
				t.Fatal("writeRecord() error = nil")
			}
			store.faults = recordFaults{}
			if err := store.writeRecord("record.json", data); err != nil {
				t.Fatalf("retry writeRecord() error = %v", err)
			}
			got, err := os.ReadFile(filepath.Join(store.path, "record.json"))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("record = %q, %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(store.path, ".record.json.publishing")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging stat error = %v", err)
			}
		})
	}
}

func TestRecordPublicationRejectsDifferentFinalRecord(t *testing.T) {
	store := newTestStore(t)
	if err := store.writeRecord("record.json", []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord("record.json", []byte("second\n")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("writeRecord() error = %v", err)
	}
}

func TestIdentifyRootMatchesDifferentPathSpellings(t *testing.T) {
	store := newTestStore(t)
	second, err := openDirectory(store.path + string(os.PathSeparator) + ".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	firstID, firstErr := IdentifyRoot(store.directory)
	secondID, secondErr := IdentifyRoot(second)
	if firstErr != nil || secondErr != nil || firstID != secondID {
		t.Fatalf("identities = %+v, %+v; errors = %v, %v", firstID, secondID, firstErr, secondErr)
	}
}

func publishTestAttempt(t *testing.T, store *Store) *Attempt {
	t.Helper()

	attempt, err := store.Begin(BeginData{
		TargetRoot: testRootIdentity, Target: "target", ExpectedSHA256: recordDigest,
		ReplacementSHA256: recordDigest, ReplacementLength: 4,
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	t.Cleanup(func() {
		if err := attempt.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if err := attempt.MarkPrepared(); err != nil {
		t.Fatalf("MarkPrepared() error = %v", err)
	}
	if err := attempt.MarkCommit(); err != nil {
		t.Fatalf("MarkCommit() error = %v", err)
	}
	effectHash, err := attempt.RecordEffect(true)
	if err != nil {
		t.Fatalf("RecordEffect() error = %v", err)
	}
	verificationHash, err := attempt.RecordVerification(Verification{
		Observed: true, ObservedSHA256: recordDigest, ObservedLength: 4, Matched: true,
	})
	if err != nil {
		t.Fatalf("RecordVerification() error = %v", err)
	}
	if _, err := attempt.Publish(StateVerified, true, effectHash, verificationHash); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	receipt, verification, err := store.inspectUnlocked(attempt.intent.AttemptID)
	if err != nil || receipt.State != StateVerified || !verification.Matched {
		t.Fatalf("Inspect() = %+v, %+v, %v", receipt, verification, err)
	}
	return attempt
}

func TestInspectRejectsTamperedRecord(t *testing.T) {
	store := newTestStore(t)
	journal, err := store.Begin(validBeginData())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Publish(StateFailed, true, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := store.root.OpenFile(
		journal.intent.AttemptID+".intent.json", os.O_WRONLY|os.O_TRUNC, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Inspect(journal.intent.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestInspectRejectsHardLinkedRecord(t *testing.T) {
	store := newTestStore(t)
	journal := publishTestAttempt(t, store)
	path := filepath.Join(store.path, journal.intent.AttemptID+".intent.json")
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.inspectUnlocked(journal.intent.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inspectUnlocked() error = %v", err)
	}
}

func TestRecoveryRejectsCorruptReceipt(t *testing.T) {
	store := newTestStore(t)
	journal := publishTestAttempt(t, store)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(store.path, journal.intent.AttemptID+".receipt.json")
	if err := os.WriteFile(receipt, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.BeginRecovery(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("BeginRecovery() error = %v", err)
	}
}

func TestInspectUsesSharedLock(t *testing.T) {
	store := newTestStore(t)
	journal := publishTestAttempt(t, store)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	shared, err := store.lockShared()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := releaseLock(shared); err != nil {
			t.Errorf("releaseLock() error = %v", err)
		}
	}()
	if _, _, err := store.Inspect(journal.intent.AttemptID); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestStoreRejectsHardLinkedOperationLock(t *testing.T) {
	store := newTestStore(t)
	path := filepath.Join(store.path, "operation.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(validBeginData()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Begin() error = %v", err)
	}
}

func TestStoreExcludesConcurrentAttempt(t *testing.T) {
	store := newTestStore(t)
	first, err := store.Begin(validBeginData())
	if err != nil {
		t.Fatalf("first Begin() error = %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	if _, err := store.Begin(validBeginData()); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second Begin() error = %v", err)
	}
	if _, _, err := store.BeginRecovery(); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("BeginRecovery() error = %v", err)
	}
	if _, _, err := store.Inspect(first.Intent().AttemptID); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestStoreRequiresRecoveryBeforeNewAttempt(t *testing.T) {
	store := newTestStore(t)
	first, err := store.Begin(validBeginData())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if second, err := store.Begin(validBeginData()); !errors.Is(err, ErrRecoveryRequired) || second != nil {
		t.Fatalf("second Begin() = %+v, %v", second, err)
	}
}

func TestStoreRequiresRecoveryForCorruptPendingAttempt(t *testing.T) {
	store := newTestStore(t)
	if err := os.WriteFile(filepath.Join(store.path, strings.Repeat("a", 43)+".intent.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if next, err := store.Begin(validBeginData()); !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, ErrCorrupt) || next != nil {
		t.Fatalf("Begin() = %+v, %v", next, err)
	}
}

func TestInspectRejectsAttemptWithoutReceipt(t *testing.T) {
	store := newTestStore(t)
	journal, err := store.Begin(validBeginData())
	if err != nil {
		t.Fatal(err)
	}
	id := journal.Intent().AttemptID
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Inspect(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestRecoverySessionPublishesPendingAttempt(t *testing.T) {
	store := newTestStore(t)
	pendingRecoveryAttempt(t, store)
	session, pending, err := store.BeginRecovery()
	if err != nil || len(pending) != 1 {
		t.Fatalf("BeginRecovery() = %+v, %v", pending, err)
	}
	verificationHash, err := session.RecordVerification(
		pending[0].Intent.AttemptID,
		Verification{Observed: true, ObservedSHA256: recordDigest, ObservedLength: 4, Matched: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Publish(pending[0], StateVerified, true, verificationHash); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if receipt, _, err := store.Inspect(pending[0].Intent.AttemptID); err != nil || receipt.State != StateVerified {
		t.Fatalf("Inspect() = %+v, %v", receipt, err)
	}
}

func TestPublicationRequiresRetainedVerification(t *testing.T) {
	store := newTestStore(t)
	pendingRecoveryAttempt(t, store)
	session, pending, err := store.BeginRecovery()
	if err != nil || len(pending) != 1 {
		t.Fatalf("BeginRecovery() = %+v, %v", pending, err)
	}
	if _, err := session.Publish(pending[0], StateVerified, true, recordDigest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Publish() error = %v", err)
	}
	if _, err := store.root.Stat(pending[0].Intent.AttemptID + ".receipt.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt Stat() error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryVerificationSurvivesInterruption(t *testing.T) {
	for _, test := range []struct {
		name    string
		record  Verification
		wantErr error
	}{
		{
			name: "unchanged",
			record: Verification{
				Observed: true, ObservedSHA256: recordDigest,
				ObservedLength: 4, Matched: true,
			},
		},
		{
			name: "changed",
			record: Verification{
				Observed: true, ObservedSHA256: strings.Repeat("1", 64),
				ObservedLength: 4,
			},
			wantErr: ErrDuplicate,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runRecoveryVerificationInterruption(t, test.record, test.wantErr)
		})
	}
}

func runRecoveryVerificationInterruption(t *testing.T, record Verification, wantErr error) {
	t.Helper()
	store := newTestStore(t)
	pendingRecoveryAttempt(t, store)
	first, pending, err := store.BeginRecovery()
	if err != nil || len(pending) != 1 {
		t.Fatalf("BeginRecovery() = %+v, %v", pending, err)
	}
	retained := Verification{
		Observed: true, ObservedSHA256: recordDigest,
		ObservedLength: 4, Matched: true,
	}
	firstDigest, err := first.RecordVerification(pending[0].Intent.AttemptID, retained)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, pending, err := store.BeginRecovery()
	if err != nil || len(pending) != 1 {
		t.Fatalf("second BeginRecovery() = %+v, %v", pending, err)
	}
	assertRecoveryVerificationRetry(t, second, pending[0], record, wantErr, firstDigest)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertRecoveryVerificationRetry(
	t *testing.T,
	session *RecoverySession,
	pending Pending,
	record Verification,
	wantErr error,
	firstDigest string,
) {
	t.Helper()
	digest, recordErr := session.RecordVerification(pending.Intent.AttemptID, record)
	if !errors.Is(recordErr, wantErr) {
		t.Fatalf("RecordVerification() = %q, %v", digest, recordErr)
	}
	if wantErr == nil {
		if digest != firstDigest {
			t.Fatalf("digest = %q, want %q", digest, firstDigest)
		}
		if _, err := session.Publish(pending, StateVerified, true, digest); err != nil {
			t.Fatal(err)
		}
	} else if _, err := session.store.root.Stat(pending.Intent.AttemptID + ".receipt.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt Stat() error = %v", err)
	}
}

func pendingRecoveryAttempt(t *testing.T, store *Store) {
	t.Helper()
	journal, err := store.Begin(validBeginData())
	if err != nil {
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
}

func TestStoreRejectsInvalidConstructionAndInput(t *testing.T) {
	if store, err := New(""); err == nil || store != nil {
		t.Fatalf("New() = %+v, %v", store, err)
	}
	store := newTestStore(t)
	invalid := validBeginData()
	invalid.ReplacementLength = 1<<20 + 1
	if attempt, err := store.Begin(invalid); !errors.Is(err, ErrCorrupt) || attempt != nil {
		t.Fatalf("Begin() = %+v, %v", attempt, err)
	}
	if _, _, err := store.Inspect("invalid"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Inspect() error = %v", err)
	}
	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil Store.Close() error = %v", err)
	}
	var nilAttempt *Attempt
	if err := nilAttempt.Close(); err != nil {
		t.Fatalf("nil Attempt.Close() error = %v", err)
	}
	var nilSession *RecoverySession
	if err := nilSession.Close(); err != nil {
		t.Fatalf("nil RecoverySession.Close() error = %v", err)
	}
}

func TestStoreRejectsUnsafeEvidenceRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if store, err := New(path); err == nil || store != nil {
		t.Fatalf("New() = %+v, %v", store, err)
	}
}

func TestInspectRejectsContradictoryVerificationRecords(t *testing.T) {
	store := newTestStore(t)
	journal := publishTestAttempt(t, store)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	record := Verification{
		Schema: SchemaVersion, AttemptID: journal.intent.AttemptID,
		Observed: true, ObservedSHA256: recordDigest, ObservedLength: 4, Matched: true,
	}
	data, _, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(journal.intent.AttemptID+".recovery-verification.json", data); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Inspect(journal.intent.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestInspectRejectsVerificationContradictingIntent(t *testing.T) {
	store := newTestStore(t)
	journal, err := store.Begin(validBeginData())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkPrepared(); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkCommit(); err != nil {
		t.Fatal(err)
	}
	effectHash, err := journal.RecordEffect(true)
	if err != nil {
		t.Fatal(err)
	}
	verification := Verification{
		Schema: SchemaVersion, AttemptID: journal.intent.AttemptID,
		Observed: true, ObservedSHA256: strings.Repeat("1", 64),
		ObservedLength: 4, Matched: true,
	}
	data, verificationHash, err := encodeRecord(verification)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(journal.intent.AttemptID+".verification.json", data); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		Schema: SchemaVersion, AttemptID: journal.intent.AttemptID,
		State: StateVerified, CleanupComplete: true,
		IntentSHA256: journal.intentHash, EffectSHA256: effectHash,
		VerificationSHA: verificationHash,
	}
	data, _, err = encodeRecord(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(journal.intent.AttemptID+".receipt.json", data); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Inspect(journal.intent.AttemptID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestRecordHelpersRejectInvalidValues(t *testing.T) {
	if _, _, err := encodeRecord(make(chan int)); err == nil {
		t.Fatal("encodeRecord() accepted an unsupported value")
	}
	for _, value := range []string{"", strings.Repeat("A", 64), strings.Repeat("0", 63)} {
		if validDigest(value) {
			t.Fatalf("validDigest(%q) = true", value)
		}
	}
	if validIdentity("not-base64") {
		t.Fatal("validIdentity() accepted invalid Base64")
	}
}

func TestStoreRejectsInvalidCheckpointGraphs(t *testing.T) {
	for _, test := range []struct {
		name   string
		record string
		value  any
	}{
		{"commit before prepared", "commit", Checkpoint{}},
		{"effect before commit", "effect", Effect{NativeSucceeded: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			journal, err := store.Begin(validBeginData())
			if err != nil {
				t.Fatal(err)
			}
			id := journal.Intent().AttemptID
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			switch value := test.value.(type) {
			case Checkpoint:
				value.Schema, value.AttemptID = SchemaVersion, id
				test.value = value
			case Effect:
				value.Schema, value.AttemptID = SchemaVersion, id
				test.value = value
			}
			data, _, err := encodeRecord(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.writeRecord(id+"."+test.record+".json", data); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.BeginRecovery(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("BeginRecovery() error = %v", err)
			}
		})
	}
}

func TestDecodeRecordRejectsMalformedForms(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("{}"),
		[]byte("{\"unknown\":true}\n"),
		[]byte("{}\n{}\n"),
		bytes.Repeat([]byte{'x'}, maxRecordBytes+1),
	} {
		var checkpoint Checkpoint
		if err := decodeRecord(data, &checkpoint); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("decodeRecord(%q) error = %v", data, err)
		}
	}
}

func TestVerificationValidationRejectsContradictions(t *testing.T) {
	intent := Intent{ReplacementSHA256: recordDigest, ReplacementLength: 4}
	for _, value := range []Verification{
		{Schema: SchemaVersion, AttemptID: "wrong", ObservedSHA256: recordDigest},
		{Schema: SchemaVersion, AttemptID: "id", ObservedSHA256: "bad"},
		{Schema: SchemaVersion, AttemptID: "id", ObservedSHA256: recordDigest, Matched: true},
		{
			Schema: SchemaVersion, AttemptID: "id", Observed: true,
			ObservedSHA256: strings.Repeat("1", 64), ObservedLength: 4, Matched: true,
		},
		{Schema: SchemaVersion, AttemptID: "id", ObservedSHA256: recordDigest, ObservedLength: 4},
		{Schema: SchemaVersion, AttemptID: "id", ObservedSHA256: recordDigest, ObservedLength: 1<<20 + 1},
	} {
		if validVerification("id", value, intent) {
			t.Fatalf("validVerification(%+v) = true", value)
		}
	}
}

func TestDecodeRecordRejectsNonCanonicalJSON(t *testing.T) {
	t.Parallel()

	var checkpoint Checkpoint
	if err := decodeRecord([]byte("{ \"schema_version\":\"x\"}\n"), &checkpoint); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("decodeRecord() error = %v", err)
	}
}

func TestExclusiveRootDACLRejectsTruncatedSID(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	ace := windows.ACCESS_ALLOWED_ACE{}
	ace.Header.AceSize = uint16(unsafe.Offsetof(ace.SidStart) + 8)
	ace.SidStart = 1 | 1<<8
	if rootACESID(&ace, user.User.Sid) {
		t.Fatal("rootACESID() accepted a SID extending beyond its ACE")
	}
}

func TestEvidenceSecurityHelpersRejectInvalidValues(t *testing.T) {
	if ownedProtectedRoot(nil) || exclusiveRootDACL(nil, nil) || validFixedRoot("relative", "relative") {
		t.Fatal("evidence security helper accepted invalid state")
	}
	if err := syncDirectory(nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("syncDirectory() error = %v", err)
	}
	if err := releaseLock(nil); err != nil {
		t.Fatalf("releaseLock(nil) error = %v", err)
	}
}

func TestEvidenceDACLRejectsWrongAccess(t *testing.T) {
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
	if ownedProtectedRoot(descriptor) {
		t.Fatal("ownedProtectedRoot() accepted read-only evidence access")
	}
}

func TestReadRecordRejectsDirectory(t *testing.T) {
	store := newTestStore(t)
	if err := store.root.Mkdir("record.json", 0o700); err != nil {
		t.Fatal(err)
	}
	var checkpoint Checkpoint
	if _, err := store.readRecord("record.json", &checkpoint); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("readRecord() error = %v", err)
	}
}

func validBeginData() BeginData {
	return BeginData{
		TargetRoot: testRootIdentity, Target: "target", ExpectedSHA256: recordDigest,
		ReplacementSHA256: recordDigest, ReplacementLength: 4,
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()

	path := filepath.Join(t.TempDir(), "evidence")
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
	store, err := New(path)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}
