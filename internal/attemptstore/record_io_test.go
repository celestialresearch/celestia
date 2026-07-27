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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecordMetadataUsesRequiredFields(t *testing.T) {
	type sample struct {
		Named    string
		Untagged string
		Optional string `json:"optional,omitempty"`
		Ignored  string `json:"-"`
	}
	fields := requiredJSONFields(sample{})
	if len(fields) != 2 || fields[0] != "Named" || fields[1] != "Untagged" {
		t.Fatalf("required fields=%v", fields)
	}
	if err := validateRecord(&sample{}); err != nil {
		t.Fatalf("unrecognised internal record rejected: %v", err)
	}
}

func TestWriteOrMatchRecordRequiresEquality(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	record := Recovery{
		Version:        Version,
		AttemptID:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		TerminalStatus: "indeterminate",
		Reason:         "interrupted",
	}
	if err := writeOrMatchRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := writeOrMatchRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("match record: %v", err)
	}
	record.Reason = "different"
	if err := writeOrMatchRecord(root, recoveryFile, record); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("different duplicate accepted: %v", err)
	}
}

func TestNewRejectsLinkedRoot(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := New(link); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked root accepted: %v", err)
	}
}

func TestPendingPublicationRefusesExistingTarget(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create directory: %v", err)
		}
	}
	if _, err := publishPendingDirectory(source, target, root); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("existing target replaced: %v", err)
	}
	if exists, err := pathExists(filepath.Join(root, "missing")); err != nil || exists {
		t.Fatalf("missing path: exists=%t error=%v", exists, err)
	}
	if exists, err := pathExists(source); err != nil || !exists {
		t.Fatalf("existing path: exists=%t error=%v", exists, err)
	}
	if _, err := pathExists("invalid\x00path"); err == nil {
		t.Fatal("invalid path accepted")
	}
}

func TestPendingPublicationRequiresSource(t *testing.T) {
	root, err := canonicalEvidenceRoot(t.TempDir())
	if err != nil {
		t.Fatalf("canonical root: %v", err)
	}
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	if err := os.RemoveAll(source); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	if err := os.RemoveAll(target); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if _, err := publishPendingDirectory(source, target, root); err == nil {
		t.Fatal("missing source published")
	}
}

func TestCanonicalEvidenceRootRejectsInvalidPath(t *testing.T) {
	if _, err := canonicalEvidenceRoot("invalid\x00path"); err == nil {
		t.Fatal("invalid evidence root accepted")
	}
}

func TestMissingAttemptCannotRecover(t *testing.T) {
	store := newTestStore(t)
	attemptID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	before, err := os.ReadDir(filepath.Join(store.root, locksDirectory))
	if err != nil {
		t.Fatalf("read locks before recovery: %v", err)
	}
	if err := store.Recover(attemptID, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing attempt recovered: %v", err)
	}
	after, err := os.ReadDir(filepath.Join(store.root, locksDirectory))
	if err != nil {
		t.Fatalf("read locks after recovery: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("missing recovery changed locks: before=%v after=%v", before, after)
	}
	if _, err := store.Inspect(attemptID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing attempt inspected: %v", err)
	}
}

func removeJSONField(t *testing.T, path, field string) {
	t.Helper()
	var record map[string]any
	readJSONFile(t, path, &record)
	delete(record, field)
	writeJSONFile(t, path, record)
}

func replaceJSONField(t *testing.T, path, field string, value any) {
	t.Helper()
	var record map[string]any
	readJSONFile(t, path, &record)
	record[field] = value
	writeJSONFile(t, path, record)
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatalf("open JSON root: %v", err)
	}
	defer func() {
		_ = root.Close()
	}()
	data, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
}
