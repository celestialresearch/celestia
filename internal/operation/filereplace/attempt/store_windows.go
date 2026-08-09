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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxRecordBytes = 64 << 10

var (
	ErrCorrupt   = errors.New("corrupt file-replacement evidence")
	ErrDuplicate = errors.New("duplicate file-replacement attempt")
	ErrLockHeld  = errors.New("file-replacement operation lock held")
)

type BeginData struct {
	Target            string
	ExpectedSHA256    string
	ReplacementSHA256 string
	ReplacementLength int64
}

type Store struct {
	path      string
	root      *os.Root
	directory *os.File
}

type Attempt struct {
	store      *Store
	lock       *os.File
	intent     Intent
	intentHash string
	closed     bool
}

type Pending struct {
	Intent           Intent
	Progress         Progress
	IntentHash       string
	EffectHash       string
	VerificationHash string
}

type RecoverySession struct {
	store  *Store
	lock   *os.File
	closed bool
}

func New(path string) (*Store, error) {
	clean, err := secureRoot(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	directory, err := openDirectory(clean)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return &Store{path: clean, root: root, directory: directory}, nil
}

func (s *Store) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	err := errors.Join(s.root.Close(), s.directory.Close())
	s.root = nil
	s.directory = nil
	return err
}

func (s *Store) Begin(data BeginData) (*Attempt, error) {
	if s == nil || s.root == nil || data.Target == "" ||
		!validDigest(data.ExpectedSHA256) || !validDigest(data.ReplacementSHA256) ||
		data.ReplacementLength < 0 || data.ReplacementLength > 1<<20 {
		return nil, ErrCorrupt
	}
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	id, err := newIdentity()
	if err != nil {
		return nil, errors.Join(err, releaseLock(lock))
	}
	intent := Intent{
		Schema: SchemaVersion, AttemptID: id, AdmittedAt: time.Now().UTC(),
		Target: data.Target, ExpectedSHA256: data.ExpectedSHA256,
		ReplacementSHA256: data.ReplacementSHA256,
		ReplacementLength: data.ReplacementLength,
		Temporary:         ".celestia-" + id + ".replace",
	}
	encoded, digest, err := encodeRecord(intent)
	if err == nil {
		err = s.writeRecord(id+".intent.json", encoded)
	}
	if err != nil {
		return nil, errors.Join(err, releaseLock(lock))
	}
	return &Attempt{store: s, lock: lock, intent: intent, intentHash: digest}, nil
}

func (s *Store) BeginRecovery() (*RecoverySession, []Pending, error) {
	lock, err := s.lock()
	if err != nil {
		return nil, nil, err
	}
	session := &RecoverySession{store: s, lock: lock}
	pending, err := s.pending()
	if err != nil {
		return nil, nil, errors.Join(err, session.Close())
	}
	return session, pending, nil
}

func (s *Store) Inspect(id string) (Receipt, Verification, error) {
	lock, err := s.lockShared()
	if err != nil {
		return Receipt{}, Verification{}, err
	}
	receipt, verification, inspectErr := s.inspectUnlocked(id)
	return receipt, verification, errors.Join(inspectErr, releaseLock(lock))
}

func (s *Store) inspectUnlocked(id string) (Receipt, Verification, error) {
	if !validIdentity(id) {
		return Receipt{}, Verification{}, ErrCorrupt
	}
	pending, err := s.loadPending(id)
	if err != nil {
		return Receipt{}, Verification{}, err
	}
	var receipt Receipt
	if _, err := s.readRecord(id+".receipt.json", &receipt); err != nil {
		return Receipt{}, Verification{}, err
	}
	if !validReceiptBinding(id, receipt, pending) {
		return Receipt{}, Verification{}, ErrCorrupt
	}
	verification, verificationHash, err := s.readTerminalVerification(id)
	if err != nil || receipt.VerificationSHA != verificationHash {
		return Receipt{}, Verification{}, ErrCorrupt
	}
	progress := pending.Progress
	if verificationHash != "" {
		progress.Observed = verification.Observed
		progress.Matched = verification.Matched
	}
	derived, err := progress.Terminal(receipt.State == StateCancelled)
	if err != nil || derived != receipt.State {
		return Receipt{}, Verification{}, ErrCorrupt
	}
	return receipt, verification, nil
}

func validReceiptBinding(id string, receipt Receipt, pending Pending) bool {
	return receipt.Schema == SchemaVersion && receipt.AttemptID == id &&
		receipt.IntentSHA256 == pending.IntentHash &&
		receipt.EffectSHA256 == pending.EffectHash
}

func (s *Store) readTerminalVerification(id string) (Verification, string, error) {
	var ordinary Verification
	ordinaryData, err := s.readOptional(id+".verification.json", &ordinary)
	if err != nil {
		return Verification{}, "", err
	}
	var recovered Verification
	recoveredData, err := s.readOptional(id+".recovery-verification.json", &recovered)
	if err != nil || ordinaryData != nil && recoveredData != nil {
		return Verification{}, "", ErrCorrupt
	}
	if ordinaryData != nil {
		if !validVerification(id, ordinary) {
			return Verification{}, "", ErrCorrupt
		}
		return ordinary, digestBytes(ordinaryData), nil
	}
	if recoveredData != nil {
		if !validVerification(id, recovered) {
			return Verification{}, "", ErrCorrupt
		}
		return recovered, digestBytes(recoveredData), nil
	}
	return Verification{}, "", nil
}

func (s *Store) pending() ([]Pending, error) {
	directory, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	var pending []Pending
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".intent.json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".intent.json")
		if _, err := s.root.Stat(id + ".receipt.json"); err == nil {
			if _, _, err := s.inspectUnlocked(id); err != nil {
				return nil, err
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		value, err := s.loadPending(id)
		if err != nil {
			return nil, err
		}
		pending = append(pending, value)
	}
	return pending, nil
}

func (s *Store) loadPending(id string) (Pending, error) {
	var intent Intent
	intentData, err := s.readRecord(id+".intent.json", &intent)
	if err != nil || !validIntent(id, intent) {
		return Pending{}, ErrCorrupt
	}
	value := Pending{Intent: intent, IntentHash: digestBytes(intentData)}
	value.Progress.Prepared, err = s.hasCheckpoint(id, "prepared")
	if err != nil {
		return Pending{}, err
	}
	value.Progress.CommitAttempted, err = s.hasCheckpoint(id, "commit")
	if err != nil {
		return Pending{}, err
	}
	var effect Effect
	effectData, effectErr := s.readOptional(id+".effect.json", &effect)
	if effectErr != nil {
		return Pending{}, effectErr
	}
	if effectData != nil {
		if effect.Schema != SchemaVersion || effect.AttemptID != id {
			return Pending{}, ErrCorrupt
		}
		value.Progress.NativeResult = true
		value.Progress.NativeSucceeded = effect.NativeSucceeded
		value.EffectHash = digestBytes(effectData)
	}
	if !validProgress(value.Progress) {
		return Pending{}, ErrCorrupt
	}
	return value, nil
}

func (s *Store) hasCheckpoint(id, name string) (bool, error) {
	var checkpoint Checkpoint
	data, err := s.readOptional(id+"."+name+".json", &checkpoint)
	if err != nil || data == nil {
		return false, err
	}
	if checkpoint.Schema != SchemaVersion || checkpoint.AttemptID != id {
		return false, ErrCorrupt
	}
	return true, nil
}

func (s *Store) readOptional(name string, target any) ([]byte, error) {
	data, err := s.readRecord(name, target)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (s *Store) readRecord(name string, target any) ([]byte, error) {
	file, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	if err := secureRecordHandle(file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if err := decodeRecord(data, target); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *RecoverySession) RecordVerification(
	id string,
	record Verification,
) (string, error) {
	record.Schema = SchemaVersion
	record.AttemptID = id
	data, digest, err := encodeRecord(record)
	if err == nil {
		err = s.store.writeRecord(id+".recovery-verification.json", data)
	}
	return digest, err
}

func (s *RecoverySession) Publish(
	pending Pending,
	state State,
	cleanup bool,
	verificationHash string,
) (Receipt, error) {
	receipt := Receipt{
		Schema: SchemaVersion, AttemptID: pending.Intent.AttemptID, State: state,
		CleanupComplete: cleanup, IntentSHA256: pending.IntentHash,
		EffectSHA256: pending.EffectHash, VerificationSHA: verificationHash,
	}
	data, _, err := encodeRecord(receipt)
	if err == nil {
		err = s.store.writeRecord(pending.Intent.AttemptID+".receipt.json", data)
	}
	return receipt, err
}

func (s *RecoverySession) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	return releaseLock(s.lock)
}

func (a *Attempt) Intent() Intent {
	return a.intent
}

func (a *Attempt) MarkPrepared() error {
	return a.writeCheckpoint("prepared")
}

func (a *Attempt) MarkCommit() error {
	return a.writeCheckpoint("commit")
}

func (a *Attempt) RecordEffect(succeeded bool) (string, error) {
	return a.write("effect", Effect{
		Schema: SchemaVersion, AttemptID: a.intent.AttemptID,
		NativeSucceeded: succeeded,
	})
}

func (a *Attempt) RecordVerification(record Verification) (string, error) {
	record.Schema = SchemaVersion
	record.AttemptID = a.intent.AttemptID
	return a.write("verification", record)
}

func (a *Attempt) Publish(
	state State,
	cleanup bool,
	effectHash,
	verificationHash string,
) (Receipt, error) {
	receipt := Receipt{
		Schema: SchemaVersion, AttemptID: a.intent.AttemptID, State: state,
		CleanupComplete: cleanup, IntentSHA256: a.intentHash,
		EffectSHA256: effectHash, VerificationSHA: verificationHash,
	}
	_, err := a.write("receipt", receipt)
	return receipt, err
}

func (a *Attempt) Close() error {
	if a == nil || a.closed {
		return nil
	}
	a.closed = true
	return releaseLock(a.lock)
}

func (a *Attempt) writeCheckpoint(name string) error {
	_, err := a.write(name, Checkpoint{Schema: SchemaVersion, AttemptID: a.intent.AttemptID})
	return err
}

func (a *Attempt) write(name string, record any) (string, error) {
	encoded, digest, err := encodeRecord(record)
	if err != nil {
		return "", err
	}
	if err := a.store.writeRecord(a.intent.AttemptID+"."+name+".json", encoded); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *Store) writeRecord(name string, data []byte) error {
	file, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr, syncDirectory(s.directory))
}

func (s *Store) lock() (*os.File, error) {
	return s.lockMode(windows.LOCKFILE_EXCLUSIVE_LOCK)
}

func (s *Store) lockShared() (*os.File, error) {
	return s.lockMode(0)
}

func (s *Store) lockMode(mode uint32) (*os.File, error) {
	file, err := s.root.OpenFile("operation.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := secureRecordHandle(file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		mode|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		err = ErrLockHeld
	}
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func releaseLock(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped windows.Overlapped
	unlockErr := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
	return errors.Join(unlockErr, file.Close())
}

func encodeRecord(record any) ([]byte, string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	data = append(data, '\n')
	if len(data) > maxRecordBytes {
		return nil, "", ErrCorrupt
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func decodeRecord(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxRecordBytes || data[len(data)-1] != '\n' {
		return ErrCorrupt
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrCorrupt
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrCorrupt
	}
	canonical, _, err := encodeRecord(target)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrCorrupt
	}
	return nil
}

func newIdentity() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func validIntent(id string, intent Intent) bool {
	return validIdentity(id) && intent.Schema == SchemaVersion &&
		intent.AttemptID == id && !intent.AdmittedAt.IsZero() &&
		intent.AdmittedAt.Location() == time.UTC && intent.Target != "" &&
		validDigest(intent.ExpectedSHA256) && validDigest(intent.ReplacementSHA256) &&
		intent.ReplacementLength >= 0 && intent.ReplacementLength <= 1<<20 &&
		intent.Temporary == ".celestia-"+id+".replace"
}

func validIdentity(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == id
}

func validVerification(id string, value Verification) bool {
	if value.Schema != SchemaVersion || value.AttemptID != id ||
		value.ObservedLength < 0 || value.ObservedLength > 1<<20 ||
		!validDigest(value.ObservedSHA256) {
		return false
	}
	return value.Observed || !value.Matched
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func secureRoot(path string) (string, error) {
	clean := filepath.Clean(path)
	if !validFixedRoot(path, clean) {
		return "", ErrCorrupt
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrCorrupt
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		clean, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	if !ownedProtectedRoot(descriptor) {
		return "", ErrCorrupt
	}
	return clean, nil
}

func ownedProtectedRoot(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	if descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	control, _, controlErr := descriptor.Control()
	if err != nil || userErr != nil || controlErr != nil || owner == nil ||
		!owner.Equals(user.User.Sid) || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	if !exclusiveRootDACL(descriptor, user.User.Sid) {
		return false
	}
	return true
}

func validFixedRoot(original, clean string) bool {
	volume := filepath.VolumeName(clean)
	if original == "" || !filepath.IsAbs(clean) || len(volume) != 2 || volume[1] != ':' {
		return false
	}
	pointer, err := windows.UTF16PtrFromString(volume + `\`)
	return err == nil && windows.GetDriveType(pointer) == windows.DRIVE_FIXED
}

func exclusiveRootDACL(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) bool {
	if descriptor == nil || user == nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE ||
		ace.Mask != windows.STANDARD_RIGHTS_ALL|0x1ff ||
		uintptr(ace.Header.AceSize) < unsafe.Offsetof(ace.SidStart)+8 {
		return false
	}
	return rootACESID(ace, user)
}

func rootACESID(ace *windows.ACCESS_ALLOWED_ACE, user *windows.SID) bool {
	// GetAce exposes the validated variable-length SID through the ACE prefix.
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- Win32 ACE layout requires this conversion.
	return sid.IsValid() && uintptr(sid.Len()) <=
		uintptr(ace.Header.AceSize)-unsafe.Offsetof(ace.SidStart) && sid.Equals(user)
}

func openDirectory(path string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH, 0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func syncDirectory(directory *os.File) error {
	if directory == nil {
		return ErrCorrupt
	}
	return windows.FlushFileBuffers(windows.Handle(directory.Fd()))
}

func secureRecordHandle(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxRecordBytes {
		return ErrCorrupt
	}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &native); err != nil {
		return err
	}
	if native.NumberOfLinks != 1 ||
		native.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return ErrCorrupt
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
