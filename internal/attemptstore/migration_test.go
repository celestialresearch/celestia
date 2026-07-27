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

package attemptstore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreResumesInterruptedMigration(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release attempt: %v", err)
	}
	marker := filepath.Join(store.root, locksDirectory, accepted.Request.AttemptID+ownershipMarkerSuffix)
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove ownership marker: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "restart"); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("incomplete migration recovered: %v", err)
	}
	if err := store.MigrateV0(accepted.Request.AttemptID, "operator resumed migration"); err != nil {
		t.Fatalf("resume migration: %v", err)
	}
	records, err := store.Inspect(accepted.Request.AttemptID)
	if err != nil || records.Recovery == nil {
		t.Fatalf("inspect resumed migration: records=%+v error=%v", records, err)
	}
}

func TestStoreRejectsMissingCurrentLock(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("release interrupted attempt: %v", err)
	}
	if err := store.MigrateV0(accepted.Request.AttemptID, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty migration reason accepted: %v", err)
	}
	if err := store.MigrateV0(accepted.Request.AttemptID, "lock still present"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("current lock migrated as legacy: %v", err)
	}
	lockPath := filepath.Join(store.root, locksDirectory, accepted.Request.AttemptID+".lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove current lock: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "missing current lock"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing current lock accepted: %v", err)
	}
}

func TestStoreMigratesFrozenPreLockV0Attempt(t *testing.T) {
	const attemptID = "u-E-mAG_fEAmsIQlu9c-Ha4JgGaejo4G2l5om4o94Wc"
	store := newTestStore(t)
	admitted, fixtureHash := frozenV0Admitted(t)
	bundlePath := filepath.Join(store.root, attemptsDirectory, pendingDirectory, attemptID, bundleDirectory)
	if err := createEvidenceDirectory(filepath.Dir(bundlePath)); err != nil {
		t.Fatalf("create frozen attempt directory: %v", err)
	}
	if err := createEvidenceDirectory(bundlePath); err != nil {
		t.Fatalf("create frozen bundle directory: %v", err)
	}
	if err := writeRecord(bundlePath, admittedFile, admitted); err != nil {
		t.Fatalf("write frozen v0 fixture: %v", err)
	}
	if err := verifyHash(bundlePath, admittedFile, fixtureHash); err != nil {
		t.Fatalf("frozen v0 fixture changed during secure publication: %v", err)
	}
	if err := store.Recover(attemptID, "legacy"); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("frozen v0 attempt recovered without migration: %v", err)
	}
	if err := store.MigrateV0(attemptID, "operator quiesced legacy attempt"); err != nil {
		t.Fatalf("migrate frozen v0 attempt: %v", err)
	}
	records, err := store.Inspect(attemptID)
	if err != nil {
		t.Fatalf("inspect migrated frozen v0 attempt: %v", err)
	}
	if records.Recovery == nil || records.Recovery.TerminalStatus != "indeterminate" {
		t.Fatalf("migrated frozen records=%+v", records)
	}
}

func TestStoreAdoptsPublishedPreLockV0Attempt(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(store.root, locksDirectory, accepted.Request.AttemptID+ownershipMarkerSuffix)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateV0(accepted.Request.AttemptID, "operator quiesced published legacy attempt"); err != nil {
		t.Fatalf("adopt published v0 attempt: %v", err)
	}
	if _, err := store.Inspect(accepted.Request.AttemptID); err != nil {
		t.Fatalf("inspect adopted attempt: %v", err)
	}
	if err := store.Recover(accepted.Request.AttemptID, "repeat recovery"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("repeat recovery: %v", err)
	}
}

func frozenV0Admitted(t *testing.T) (Admitted, string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join("testdata", "pre-lock-v0"))
	if err != nil {
		t.Fatalf("open frozen v0 fixtures: %v", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close frozen v0 fixtures: %v", err)
		}
	}()
	encoded, err := root.ReadFile("admitted.json.b64")
	if err != nil {
		t.Fatalf("read frozen v0 fixture: %v", err)
	}
	fixture, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode frozen v0 fixture: %v", err)
	}
	sum := sha256.Sum256(fixture)
	hash := hex.EncodeToString(sum[:])
	const expectedHash = "4cb55d105f0198e45b4549336824d482688a0b3fc751ff415cd28439ee1eb61d"
	if hash != expectedHash {
		t.Fatalf("frozen v0 fixture hash=%s want=%s", hash, expectedHash)
	}
	var admitted Admitted
	if err := json.Unmarshal(fixture, &admitted); err != nil {
		t.Fatalf("decode frozen v0 admitted record: %v", err)
	}
	if err := validateAdmitted(admitted); err != nil {
		t.Fatalf("validate frozen v0 admitted record: %v", err)
	}
	return admitted, hash
}
