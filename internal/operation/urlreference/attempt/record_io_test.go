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

//go:build windows

package attemptstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type failingRecordWriter struct {
	name       string
	chmodErr   error
	writeErr   error
	shortWrite bool
	syncErr    error
	closeErr   error
	closeCalls int
}

func TestReadRootedReportsPostInspectionOpenFailure(t *testing.T) {
	t.Parallel()
	root := protectedTestDirectory(t)
	name := recoveryFile
	if err := writeRecord(root, name, map[string]string{"value": "fixture"}); err != nil {
		t.Fatalf("write record: %v", err)
	}
	failure := errors.New("injected record open failure")
	_, err := readRootedWith(
		root,
		name,
		func(*os.Root, string) (*os.File, error) { return nil, failure },
	)
	if !errors.Is(err, failure) {
		t.Fatalf("readRootedWith() error = %v", err)
	}
}

func (writer *failingRecordWriter) Name() string {
	return writer.name
}

func (writer *failingRecordWriter) Chmod(os.FileMode) error {
	return writer.chmodErr
}

func (writer *failingRecordWriter) Write(data []byte) (int, error) {
	if writer.writeErr != nil {
		return 0, writer.writeErr
	}
	if writer.shortWrite {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (writer *failingRecordWriter) Sync() error {
	return writer.syncErr
}

func (writer *failingRecordWriter) Close() error {
	writer.closeCalls++
	return writer.closeErr
}

type failingRecordReader struct {
	info    os.FileInfo
	statErr error
	readErr error
	data    []byte
}

func (reader *failingRecordReader) Stat() (os.FileInfo, error) {
	return reader.info, reader.statErr
}

func (reader *failingRecordReader) Read(buffer []byte) (int, error) {
	if reader.readErr != nil {
		return 0, reader.readErr
	}
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(buffer, reader.data)
	reader.data = reader.data[count:]
	return count, nil
}

func TestWriteRecordFilePropagatesFailures(t *testing.T) {
	injected := errors.New("injected record failure")
	cases := []struct {
		name   string
		writer failingRecordWriter
	}{
		{name: "chmod", writer: failingRecordWriter{chmodErr: injected}},
		{name: "write", writer: failingRecordWriter{writeErr: injected}},
		{name: "short write", writer: failingRecordWriter{shortWrite: true}},
		{name: "sync", writer: failingRecordWriter{syncErr: injected}},
		{name: "close", writer: failingRecordWriter{closeErr: injected}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			temporary := filepath.Join(t.TempDir(), "record.tmp")
			if err := os.WriteFile(temporary, nil, 0o600); err != nil {
				t.Fatalf("create temporary record: %v", err)
			}
			test.writer.name = temporary
			err := writeRecordFile(t.TempDir(), "record.json", []byte("{}"), &test.writer)
			want := injected
			if test.writer.shortWrite {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) {
				t.Fatalf("record failure = %v, want %v", err, want)
			}
			if test.writer.closeCalls != 1 {
				t.Fatalf("close calls = %d", test.writer.closeCalls)
			}
			if _, err := os.Stat(temporary); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary record remains: %v", err)
			}
		})
	}
}

func TestWriteRecordFilePropagatesPublicationFailures(t *testing.T) {
	t.Parallel()

	statErr := errors.New("stat target")
	publishErr := errors.New("publish target")
	for _, test := range []struct {
		name    string
		stat    func(string) (os.FileInfo, error)
		publish func(string, string, string) error
		want    error
	}{
		{
			name: "target stat",
			stat: func(string) (os.FileInfo, error) {
				return nil, statErr
			},
			publish: func(string, string, string) error {
				t.Fatal("publish called after stat failure")
				return nil
			},
			want: statErr,
		},
		{
			name: "publication",
			stat: func(string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
			publish: func(string, string, string) error {
				return publishErr
			},
			want: publishErr,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			temporary := filepath.Join(t.TempDir(), "record.tmp")
			if err := os.WriteFile(temporary, nil, 0o600); err != nil {
				t.Fatalf("create temporary record: %v", err)
			}
			writer := failingRecordWriter{name: temporary}
			err := writeRecordFileWith(
				t.TempDir(),
				"record.json",
				[]byte("{}"),
				&writer,
				test.stat,
				test.publish,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("record failure = %v, want %v", err, test.want)
			}
			if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary record remains: %v", err)
			}
		})
	}
}

func TestReadRecordFilePropagatesFailures(t *testing.T) {
	injected := errors.New("injected record failure")
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
	if err := writeRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("write record: %v", err)
	}
	file := filepath.Join(root, recoveryFile)
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat record: %v", err)
	}
	cases := []struct {
		name   string
		reader failingRecordReader
		want   error
	}{
		{name: "stat", reader: failingRecordReader{statErr: injected}, want: injected},
		{name: "read", reader: failingRecordReader{info: info, readErr: injected}, want: injected},
		{
			name:   "oversized",
			reader: failingRecordReader{info: info, data: make([]byte, maxRecordBytes+1)},
			want:   ErrCorrupt,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readRecordFile(file, &test.reader); !errors.Is(err, test.want) {
				t.Fatalf("read error = %v, want %v", err, test.want)
			}
		})
	}
	directoryInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if _, err := readRecordFile(file, &failingRecordReader{info: directoryInfo}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory accepted: %v", err)
	}
}

func TestDecodeRecordRejectsUnknownFields(t *testing.T) {
	var recovery Recovery
	encoded := []byte(
		`{"version":1,` +
			`"attempt_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
			`"terminal_status":"indeterminate","reason":"interrupted","extra":true}`,
	)
	if err := decodeRecord(encoded, &recovery); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown field accepted: %v", err)
	}
}

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

func TestWriteOrMatchRecordRejectsCorruptDuplicate(t *testing.T) {
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
	if err := writeRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, recoveryFile), []byte("{}"), 0o600); err != nil {
		t.Fatalf("corrupt record: %v", err)
	}
	if err := writeOrMatchRecord(root, recoveryFile, record); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt duplicate accepted: %v", err)
	}
}

func TestReadRootedRejectsLinkedAncestor(t *testing.T) {
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
	if err := writeRecord(root, recoveryFile, record); err != nil {
		t.Fatalf("write record: %v", err)
	}
	link := filepath.Join(t.TempDir(), "evidence-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("create linked ancestor: %v", err)
	}
	if _, err := readRooted(link, recoveryFile); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked ancestor accepted: %v", err)
	}
}

func TestNewRejectsLinkedRoot(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create linked root: %v", err)
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

func TestPendingPublicationRejectsInvalidTarget(t *testing.T) {
	if _, err := publishPendingDirectory(
		t.TempDir(),
		"invalid\x00target",
		t.TempDir(),
	); err == nil {
		t.Fatal("invalid publication target accepted")
	}
}

func TestCanonicalEvidenceRootRejectsInvalidPath(t *testing.T) {
	if _, err := canonicalEvidenceRoot("invalid\x00path"); err == nil {
		t.Fatal("invalid evidence root accepted")
	}
}

func TestCanonicalEvidenceRootRejectsBrokenLink(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "missing"), link); err != nil {
		t.Fatalf("create broken link: %v", err)
	}
	if _, err := canonicalEvidenceRoot(filepath.Join(link, "child")); err == nil {
		t.Fatal("broken-link root accepted")
	}
}

func TestBundleValidationRejectsInvalidRoot(t *testing.T) {
	if err := validateBundleFiles("invalid\x00path", observationFile, true); err == nil {
		t.Fatal("invalid bundle root accepted")
	}
	file := filepath.Join(t.TempDir(), "bundle-file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}
	if err := validateBundleFiles(file, observationFile, true); err == nil {
		t.Fatal("bundle file accepted as a directory")
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
		if err := root.Close(); err != nil {
			t.Errorf("close JSON root: %v", err)
		}
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

func TestReadRecordRejectsNonCanonicalJSON(t *testing.T) {
	root := t.TempDir()
	recovery := Recovery{
		Version:        Version,
		AttemptID:      strings.Repeat("A", 43),
		TerminalStatus: "indeterminate",
		Reason:         "fixture",
	}
	canonical, err := json.Marshal(recovery)
	if err != nil {
		t.Fatalf("encode recovery: %v", err)
	}
	tests := map[string][]byte{
		"leading whitespace": append([]byte(" "), canonical...),
		"duplicate field": append(
			bytes.TrimSuffix(canonical, []byte("}")),
			[]byte(`,"version":1}`)...,
		),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write record: %v", err)
			}
			var actual Recovery
			if err := readRecord(root, filepath.Base(path), &actual); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("non-canonical record accepted: %v", err)
			}
		})
	}
}

func TestReadRootedBoundsEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "large.json"),
		make([]byte, maxRecordBytes+1),
		0o600,
	); err != nil {
		t.Fatalf("write large record: %v", err)
	}
	if _, err := readRooted(root, "large.json"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("large record accepted: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatalf("create directory record: %v", err)
	}
	if _, err := readRooted(root, "directory"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory record accepted: %v", err)
	}
}

func TestStoreRejectsRecordOutsideEvidenceBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-bundle")
	if err := writeRecord(path, admittedFile, Admitted{}); err == nil {
		t.Fatal("record written outside an evidence bundle")
	}
}

func TestStoreRejectsUnserialisableRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle")
	if err := createEvidenceDirectory(path); err != nil {
		t.Fatalf("create record bundle: %v", err)
	}
	if err := writeRecord(path, "invalid.json", make(chan int)); err == nil {
		t.Fatal("unserialisable record accepted")
	}
}

func TestStoreRejectsDuplicateAndInvalidRecords(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := store.Stage(accepted, admittedAt); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate stage: %v", err)
	}
	observation := testObservation("invalid")
	if err := attempt.Publish(observation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid observation: %v", err)
	}
	observation = testObservation(accepted.Request.AttemptID)
	if err := attempt.Publish(observation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("released attempt published: %v", err)
	}
	for _, reason := range []string{
		"",
		" ",
		"line\nbreak",
		string([]byte{0xff}),
		strings.Repeat("x", maxRecoveryReasonBytes+1),
	} {
		if err := store.Recover(accepted.Request.AttemptID, reason); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid recovery reason %q: %v", reason, err)
		}
	}
	if _, err := store.Inspect("invalid"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid identity: %v", err)
	}
	if _, err := store.Inspect(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical identity: %v", err)
	}
}

func TestStoreReportsWriteFailure(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	cleanupAttempt(t, attempt)
	if err := os.Rename(attempt.path, attempt.path+".moved"); err != nil {
		t.Fatalf("move attempt: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err == nil {
		t.Fatal("missing attempt directory accepted publication")
	}
}

func TestStoreRejectsMalformedRecords(t *testing.T) {
	store := newTestStore(t)
	accepted, admittedAt := testAccepted(t)
	attempt, err := store.Stage(accepted, admittedAt)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := attempt.Publish(testObservationFor(t, accepted)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	path := store.finalPath(accepted.Request.AttemptID)
	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "admitted JSON", file: "admitted.json", data: []byte("{")},
		{name: "receipt JSON", file: "receipt.json", data: []byte("{}{}")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(path, test.file)
			original, readErr := readRooted(path, test.file)
			if readErr != nil {
				t.Fatalf("read record: %v", readErr)
			}
			if writeErr := os.WriteFile(target, test.data, 0o600); writeErr != nil {
				t.Fatalf("write malformed record: %v", writeErr)
			}
			if _, inspectErr := store.Inspect(accepted.Request.AttemptID); inspectErr == nil {
				t.Fatal("malformed record was accepted")
			}
			if writeErr := os.WriteFile(target, original, 0o600); writeErr != nil {
				t.Fatalf("restore record: %v", writeErr)
			}
		})
	}
}

func TestWriteRecordRejectsDuplicate(t *testing.T) {
	root := t.TempDir()
	if err := writeRecord(root, "record.json", map[string]int{"value": 1}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeRecord(root, "record.json", map[string]int{"value": 2}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate write: %v", err)
	}
	if err := writeRecord(filepath.Join(root, "missing"), "record.json", struct{}{}); err == nil {
		t.Fatal("missing directory accepted write")
	}
}

func TestWriteRecordRejectsOversizedEncodingBeforeTemporaryFile(t *testing.T) {
	root := t.TempDir()
	if err := writeRecord(root, "large.json", strings.Repeat("x", maxRecordBytes)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized record: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(root, ".large.json.*"))
	if err != nil {
		t.Fatalf("glob temporary records: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("oversized record left temporary files: %v", matches)
	}
}
