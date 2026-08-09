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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"celestia.research/celestia/internal/operation/filereplace/admission"
	"celestia.research/celestia/internal/operation/filereplace/attempt"
)

type platformOperation struct {
	targetPath string
	target     *os.Root
	directory  *os.File
	targetID   attempt.RootIdentity
	store      *attempt.Store
	faults     operationFaults
}

type operationFaults struct {
	beforeFinalCheck          func()
	afterCommit               func()
	afterRecoveryVerification func()
	targetSync                error
	effectRecord              error
	verification              error
	cleanup                   error
	partialWrite              bool
	publication               error
}

func newPlatformOperation(config Config) (platformOperation, error) {
	targetPath, err := secureTargetRoot(config.TargetRoot)
	if err != nil {
		return platformOperation{}, errors.Join(ErrConfiguration, err)
	}
	target, err := os.OpenRoot(targetPath)
	if err != nil {
		return platformOperation{}, errors.Join(ErrConfiguration, err)
	}
	directory, err := openTargetDirectory(targetPath)
	if err != nil {
		return platformOperation{}, errors.Join(ErrConfiguration, err, target.Close())
	}
	targetID, err := attempt.IdentifyRoot(directory)
	if err != nil {
		return platformOperation{}, errors.Join(ErrConfiguration, err, target.Close(), directory.Close())
	}
	store, err := attempt.New(config.EvidenceRoot)
	if err != nil {
		return platformOperation{}, errors.Join(
			ErrConfiguration, err, target.Close(), directory.Close(),
		)
	}
	if targetID == store.Identity() {
		return platformOperation{}, errors.Join(
			ErrConfiguration, store.Close(), target.Close(), directory.Close(),
		)
	}
	return platformOperation{
		targetPath: targetPath, target: target, directory: directory,
		targetID: targetID, store: store,
	}, nil
}

func (p *platformOperation) execute(
	ctx context.Context,
	request admission.Request,
) (result Result, err error) {
	if p.store == nil || p.target == nil || p.directory == nil {
		return Result{}, ErrConfiguration
	}
	replacement := request.Replacement()
	replacementHash := sha256.Sum256(replacement)
	expectedHash := request.ExpectedSHA256()
	journal, err := p.store.Begin(attempt.BeginData{
		TargetRoot:        p.targetID,
		Target:            request.Target(),
		ExpectedSHA256:    hex.EncodeToString(expectedHash[:]),
		ReplacementSHA256: hex.EncodeToString(replacementHash[:]),
		ReplacementLength: int64(len(replacement)),
	})
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if closeErr := journal.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	result.AttemptID = journal.Intent().AttemptID
	return p.executeAttempt(ctx, journal, request, replacement, replacementHash, result)
}

func (p *platformOperation) executeAttempt(
	ctx context.Context,
	journal *attempt.Attempt,
	request admission.Request,
	replacement []byte,
	replacementHash [32]byte,
	result Result,
) (Result, error) {
	temporary := journal.Intent().Temporary
	if err := p.prepare(temporary, replacement); err != nil {
		return p.finishBeforeCommit(journal, result, false, temporary, err)
	}
	if err := journal.MarkPrepared(); err != nil {
		return p.finishBeforeCommit(journal, result, false, temporary, err)
	}
	if err := ctx.Err(); err != nil {
		return p.finishBeforeCommit(journal, result, true, temporary, err)
	}
	if err := p.checkPrecondition(request); err != nil {
		return p.finishBeforeCommit(journal, result, false, temporary, err)
	}
	if p.faults.beforeFinalCheck != nil {
		p.faults.beforeFinalCheck()
	}
	if err := p.checkPrecondition(request); err != nil {
		return p.finishBeforeCommit(journal, result, false, temporary, err)
	}
	if err := journal.MarkCommit(); err != nil {
		return p.finishBeforeCommit(journal, result, false, temporary, err)
	}
	if err := p.target.Rename(temporary, request.Target()); err != nil {
		effectHash, recordErr := p.recordEffect(journal, false)
		removeErr := p.removeTemporary(temporary)
		if removeErr != nil {
			p.faults.cleanup = errors.Join(p.faults.cleanup, removeErr)
		}
		if recordErr != nil {
			result.State = attempt.StateIndeterminate
			result.CleanupComplete = removeErr == nil
			return result, errors.Join(ErrIndeterminate, err, recordErr, removeErr)
		}
		return p.finish(journal, result, attempt.Progress{
			Prepared: true, CommitAttempted: true, NativeResult: true,
		}, effectHash, "", errors.Join(err, recordErr, removeErr))
	}
	return p.finishCommitted(journal, request, replacement, replacementHash, result)
}

func (p *platformOperation) finishCommitted(
	journal *attempt.Attempt,
	request admission.Request,
	replacement []byte,
	replacementHash [32]byte,
	result Result,
) (Result, error) {
	if p.faults.afterCommit != nil {
		p.faults.afterCommit()
	}
	syncErr := p.syncTarget()
	effectHash, effectErr := p.recordEffect(journal, true)
	observed, length, observeErr := inspectTarget(p.target, request.Target())
	matched := observeErr == nil && observed == replacementHash && length == int64(len(replacement))
	verificationHash, verificationErr := "", p.faults.verification
	if verificationErr == nil {
		verificationHash, verificationErr = journal.RecordVerification(attempt.Verification{
			Observed: observeErr == nil, ObservedSHA256: hex.EncodeToString(observed[:]),
			ObservedLength: length, Matched: matched,
		})
	}
	result.ObservedSHA256 = observed
	progress := attempt.Progress{
		Prepared: true, CommitAttempted: true, NativeResult: true,
		NativeSucceeded: true, Observed: observeErr == nil, Matched: matched,
	}
	checkpointErr := errors.Join(syncErr, effectErr, verificationErr)
	if checkpointErr != nil {
		result.State = attempt.StateIndeterminate
		result.CleanupComplete = true
		return result, errors.Join(ErrIndeterminate, checkpointErr, observeErr)
	}
	return p.finish(
		journal, result, progress, effectHash, verificationHash,
		observeErr,
	)
}

func (p *platformOperation) checkPrecondition(request admission.Request) error {
	observed, _, err := inspectTarget(p.target, request.Target())
	if err != nil {
		return err
	}
	if observed != request.ExpectedSHA256() {
		return ErrPrecondition
	}
	return nil
}

func (p *platformOperation) prepare(name string, replacement []byte) error {
	file, err := p.target.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	content := replacement
	if p.faults.partialWrite && len(content) != 0 {
		content = content[:len(content)/2]
	}
	written, writeErr := file.Write(content)
	if p.faults.partialWrite && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Sync(), file.Close(), syncTargetDirectory(p.directory))
}

func (p *platformOperation) finishBeforeCommit(
	journal *attempt.Attempt,
	result Result,
	cancelled bool,
	temporary string,
	cause error,
) (Result, error) {
	removeErr := p.removeTemporary(temporary)
	if removeErr != nil {
		p.faults.cleanup = errors.Join(p.faults.cleanup, removeErr)
	}
	progress := attempt.Progress{Prepared: true}
	return p.finish(journal, result, progress, "", "", errors.Join(cause, removeErr), cancelled)
}

func (p *platformOperation) removeTemporary(name string) error {
	err := p.target.Remove(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return p.syncTarget()
}

func (p *platformOperation) syncTarget() error {
	return errors.Join(syncTargetDirectory(p.directory), p.faults.targetSync)
}

func (p *platformOperation) recordEffect(
	journal *attempt.Attempt,
	succeeded bool,
) (string, error) {
	if p.faults.effectRecord != nil {
		return "", p.faults.effectRecord
	}
	return journal.RecordEffect(succeeded)
}

func (p *platformOperation) finish(
	journal *attempt.Attempt,
	result Result,
	progress attempt.Progress,
	effectHash,
	verificationHash string,
	causes error,
	cancelled ...bool,
) (Result, error) {
	state, stateErr := progress.Terminal(len(cancelled) != 0 && cancelled[0])
	result.State = state
	result.CleanupComplete = p.faults.cleanup == nil
	publishErr := p.faults.publication
	if publishErr == nil {
		_, publishErr = journal.Publish(
			state, result.CleanupComplete, effectHash, verificationHash,
		)
	} else if progress.CommitAttempted {
		result.State = attempt.StateIndeterminate
		state = attempt.StateIndeterminate
	}
	err := errors.Join(causes, stateErr, publishErr, p.faults.cleanup)
	if state == attempt.StateIndeterminate {
		err = errors.Join(ErrIndeterminate, err)
	}
	return result, err
}

func (p *platformOperation) recover(ctx context.Context) (results []Result, err error) {
	if p.store == nil || p.target == nil || p.directory == nil {
		return nil, ErrConfiguration
	}
	session, pending, err := p.store.BeginRecovery()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	for _, value := range pending {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		result, recoverErr := p.recoverAttempt(session, value)
		results = append(results, result)
		if recoverErr != nil {
			return results, recoverErr
		}
	}
	return results, nil
}

func (p *platformOperation) recoverAttempt(
	session *attempt.RecoverySession,
	pending attempt.Pending,
) (Result, error) {
	result := Result{AttemptID: pending.Intent.AttemptID}
	if pending.Intent.TargetRoot != p.targetID {
		return result, errors.Join(ErrConfiguration, attempt.ErrCorrupt)
	}
	if !pending.Progress.CommitAttempted {
		removeErr := p.removeTemporary(pending.Intent.Temporary)
		result.State = attempt.StateFailed
		result.CleanupComplete = removeErr == nil
		_, publishErr := session.Publish(pending, result.State, result.CleanupComplete, "")
		return result, errors.Join(removeErr, publishErr)
	}
	if err := p.syncTarget(); err != nil {
		result.State = attempt.StateIndeterminate
		return result, errors.Join(ErrIndeterminate, err)
	}
	observed, length, observeErr := inspectTarget(p.target, pending.Intent.Target)
	replacement, decodeErr := decodeSHA256(pending.Intent.ReplacementSHA256)
	matched := observeErr == nil && decodeErr == nil && observed == replacement &&
		length == pending.Intent.ReplacementLength
	verificationHash, recordErr := session.RecordVerification(
		pending.Intent.AttemptID,
		attempt.Verification{
			Observed: observeErr == nil, ObservedSHA256: hex.EncodeToString(observed[:]),
			ObservedLength: length, Matched: matched,
		},
	)
	if recordErr == nil && p.faults.afterRecoveryVerification != nil {
		p.faults.afterRecoveryVerification()
	}
	progress := pending.Progress
	progress.Observed = observeErr == nil
	progress.Matched = matched
	state, stateErr := progress.Terminal(false)
	result.State = state
	result.ObservedSHA256 = observed
	result.CleanupComplete = true
	if recordErr != nil {
		return result, errors.Join(ErrIndeterminate, decodeErr, observeErr, recordErr, stateErr)
	}
	_, publishErr := session.Publish(pending, state, true, verificationHash)
	err := errors.Join(decodeErr, observeErr, stateErr, publishErr)
	if state == attempt.StateIndeterminate {
		err = errors.Join(ErrIndeterminate, err)
	}
	return result, err
}

func decodeSHA256(value string) ([32]byte, error) {
	var digest [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, attempt.ErrCorrupt
	}
	copy(digest[:], decoded)
	return digest, nil
}

func (p *platformOperation) close() error {
	if p == nil {
		return nil
	}
	var targetErr, directoryErr, storeErr error
	if p.target != nil {
		targetErr = p.target.Close()
		p.target = nil
	}
	if p.directory != nil {
		directoryErr = p.directory.Close()
		p.directory = nil
	}
	if p.store != nil {
		storeErr = p.store.Close()
		p.store = nil
	}
	return errors.Join(targetErr, directoryErr, storeErr)
}

func (p *platformOperation) inspect(id string) (Result, error) {
	if p.store == nil {
		return Result{}, ErrConfiguration
	}
	receipt, verification, err := p.store.Inspect(id)
	if err != nil {
		return Result{}, err
	}
	observed, decodeErr := decodeSHA256(verification.ObservedSHA256)
	if receipt.VerificationSHA == "" {
		observed = [32]byte{}
		decodeErr = nil
	}
	return Result{
		AttemptID: id, State: receipt.State, ObservedSHA256: observed,
		CleanupComplete: receipt.CleanupComplete,
	}, decodeErr
}

func inspectTarget(root *os.Root, name string) ([32]byte, int64, error) {
	file, err := root.Open(name)
	if err != nil {
		return [32]byte{}, 0, err
	}
	digest, length, inspectErr := inspectTargetFile(file)
	return digest, length, errors.Join(inspectErr, file.Close())
}

func inspectTargetFile(file *os.File) ([32]byte, int64, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 ||
		info.Size() > admission.MaxReplacementBytes {
		return [32]byte{}, 0, ErrTarget
	}
	if err := secureTargetHandle(file); err != nil {
		return [32]byte{}, 0, err
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, info.Size()+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return [32]byte{}, 0, err
	}
	if written != info.Size() {
		return [32]byte{}, 0, ErrTarget
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, info.Size(), nil
}
