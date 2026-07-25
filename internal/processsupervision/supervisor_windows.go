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

package processsupervision

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errStreamLimit = errors.New("process stream limit exceeded")

type Supervisor struct {
	workerPath string
	workerHash [32]byte
	limits     Limits
}

type pipeSet struct {
	stdinRead   windows.Handle
	stdinWrite  windows.Handle
	stdoutRead  windows.Handle
	stdoutWrite windows.Handle
	stderrRead  windows.Handle
	stderrWrite windows.Handle
}

type launchedProcess struct {
	info      windows.ProcessInformation
	job       windows.Handle
	pipes     pipeSet
	container appContainer
	image     *os.File
	started   time.Time
}

type launchResources struct {
	container appContainer
	image     *os.File
	imagePath string
	imageHash [32]byte
	pipes     pipeSet
	job       windows.Handle
	cleanup   time.Duration
}

type streamResult struct {
	data []byte
	err  error
}

type jobAccounting struct {
	totalUserTime             int64
	totalKernelTime           int64
	thisPeriodTotalUserTime   int64
	thisPeriodTotalKernelTime int64
	totalPageFaultCount       uint32
	totalProcesses            uint32
	activeProcesses           uint32
	totalTerminatedProcesses  uint32
}

func newSupervisor(workerPath string, limits Limits) (*Supervisor, error) {
	if workerPath == "" || !filepath.IsAbs(workerPath) || !validLimits(limits) {
		return nil, fmt.Errorf("%w: worker path or limits", ErrInvalid)
	}
	pathPointer, err := windows.UTF16PtrFromString(workerPath)
	if err != nil {
		return nil, fmt.Errorf("%w: worker path encoding", ErrInvalid)
	}
	attributes, err := windows.GetFileAttributes(pathPointer)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect worker: %w", ErrInvalid, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("%w: worker must be a regular non-reparse file", ErrInvalid)
	}
	cleanPath := filepath.Clean(workerPath)
	worker, err := openLocked(cleanPath, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, fmt.Errorf("%w: open worker: %w", ErrInvalid, err)
	}
	hash, hashErr := hashFile(worker)
	closeErr := worker.Close()
	if err := errors.Join(hashErr, closeErr); err != nil {
		return nil, fmt.Errorf("%w: measure worker: %w", ErrInvalid, err)
	}
	return &Supervisor{
		workerPath: cleanPath,
		workerHash: hash,
		limits:     limits,
	}, nil
}

func validLimits(limits Limits) bool {
	return limits.InputBytes > 0 &&
		limits.OutputBytes > 0 &&
		limits.ErrorBytes > 0 &&
		limits.MemoryBytes > 0 &&
		limits.Processes > 0 &&
		limits.Timeout > 0 &&
		limits.CleanupTimeout > 0
}

func (supervisor *Supervisor) run(ctx context.Context, frame []byte) Outcome {
	started := time.Now()
	if ctx == nil || len(frame) == 0 || len(frame) > supervisor.limits.InputBytes {
		return failedOutcome(StartFailed, started, fmt.Errorf("%w: context or frame", ErrInvalid))
	}
	select {
	case <-ctx.Done():
		return failedOutcome(Cancelled, started, ctx.Err())
	default:
	}
	process, hash, err := supervisor.launch()
	if err != nil {
		outcome := failedOutcome(StartFailed, started, err)
		outcome.WorkerSHA256 = supervisor.workerHash
		if hash != ([32]byte{}) {
			outcome.WorkerSHA256 = hash
		}
		return outcome
	}
	remaining := supervisor.limits.Timeout - time.Since(started)
	outcome := supervisor.observe(ctx, process, frame, remaining)
	outcome.WorkerSHA256 = hash
	outcome.Duration = time.Since(started)
	return outcome
}

func (supervisor *Supervisor) launch() (*launchedProcess, [32]byte, error) {
	resources, err := supervisor.prepareLaunch()
	if err != nil {
		return nil, [32]byte{}, err
	}
	process, err := resources.start()
	if err != nil {
		return nil, resources.imageHash, errors.Join(err, resources.close())
	}
	return process, resources.imageHash, nil
}

func (supervisor *Supervisor) prepareLaunch() (*launchResources, error) {
	container, err := createContainerName()
	if err != nil {
		if container.name != "" {
			err = errors.Join(err, container.close())
		}
		return nil, err
	}
	image, hash, imagePath, err := stageImage(container.folder, supervisor.workerPath)
	if err != nil {
		return nil, errors.Join(err, container.close())
	}
	if hash != supervisor.workerHash {
		return nil, errors.Join(
			errors.New("configured worker identity changed"),
			image.Close(),
			container.close(),
		)
	}
	pipes, err := newPipes()
	if err != nil {
		return nil, errors.Join(err, image.Close(), container.close())
	}
	job, err := createJob(supervisor.limits)
	if err != nil {
		pipes.close()
		return nil, errors.Join(err, image.Close(), container.close())
	}
	return &launchResources{
		container: container,
		image:     image,
		imagePath: imagePath,
		imageHash: hash,
		pipes:     pipes,
		job:       job,
		cleanup:   supervisor.limits.CleanupTimeout,
	}, nil
}

func (resources *launchResources) start() (*launchedProcess, error) {
	info, err := startSuspended(resources.container, resources.imagePath, resources.pipes)
	if err != nil {
		return nil, err
	}
	if err := windows.AssignProcessToJobObject(resources.job, info.Process); err != nil {
		stopErr := resources.stopStart(info, false)
		return nil, errors.Join(
			fmt.Errorf("assign worker job: %w", err),
			stopErr,
		)
	}
	resources.pipes.closeChildEnds()
	if _, err := windows.ResumeThread(info.Thread); err != nil {
		stopErr := resources.stopStart(info, true)
		return nil, errors.Join(
			fmt.Errorf("resume worker: %w", err),
			stopErr,
		)
	}
	_ = windows.CloseHandle(info.Thread)
	info.Thread = 0
	return &launchedProcess{
		info:      info,
		job:       resources.job,
		pipes:     resources.pipes,
		container: resources.container,
		image:     resources.image,
		started:   time.Now(),
	}, nil
}

func (resources *launchResources) stopStart(
	info windows.ProcessInformation,
	assigned bool,
) error {
	resources.pipes.closeChildEnds()
	var stopErr error
	if assigned {
		stopErr = windows.TerminateJobObject(resources.job, 1)
	} else {
		stopErr = windows.TerminateProcess(info.Process, 1)
	}
	complete, waitErr := waitCleanup(
		info.Process,
		resources.job,
		resources.cleanup,
	)
	if !complete && waitErr == nil {
		waitErr = errors.New("startup cleanup incomplete")
	}
	return errors.Join(
		stopErr,
		waitErr,
		windows.CloseHandle(info.Thread),
		windows.CloseHandle(info.Process),
	)
}

func (resources *launchResources) close() error {
	resources.pipes.close()
	var closeErr error
	if resources.job != 0 {
		closeErr = errors.Join(closeErr, windows.CloseHandle(resources.job))
	}
	if resources.image != nil {
		closeErr = errors.Join(closeErr, resources.image.Close())
	}
	closeErr = errors.Join(closeErr, resources.container.close())
	return closeErr
}

func (supervisor *Supervisor) observe(
	ctx context.Context,
	process *launchedProcess,
	frame []byte,
	remaining time.Duration,
) Outcome {
	stdout := make(chan streamResult, 1)
	stderr := make(chan streamResult, 1)
	overflow := make(chan Status, 2)
	stdoutHandle := process.pipes.stdoutRead
	stderrHandle := process.pipes.stderrRead
	process.pipes.stdoutRead = 0
	process.pipes.stderrRead = 0
	stdoutReader := newStreamReader("output", stdoutHandle)
	stderrReader := newStreamReader("diagnostics", stderrHandle)
	go stdoutReader.read(supervisor.limits.OutputBytes, OutputOverflow, stdout, overflow)
	go stderrReader.read(supervisor.limits.ErrorBytes, ErrorOverflow, stderr, overflow)
	input := make(chan error, 1)
	inputDone := make(chan error, 1)
	stdinHandle := process.pipes.stdinWrite
	process.pipes.stdinWrite = 0
	go func() {
		result := writeFrame(stdinHandle, frame)
		input <- result
		inputDone <- result
	}()

	waited := make(chan error, 1)
	go func() {
		_, err := windows.WaitForSingleObject(process.info.Process, windows.INFINITE)
		waited <- err
	}()
	if remaining <= 0 {
		remaining = time.Nanosecond
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()

	status, cause := awaitProcess(ctx, timer.C, waited, overflow, input)
	if status != Completed {
		if err := windows.TerminateJobObject(process.job, 1); err != nil {
			status = CleanupFailed
			cause = errors.Join(cause, fmt.Errorf("terminate job: %w", err))
		}
	}
	cleanupComplete, waitErr := waitCleanup(
		process.info.Process,
		process.job,
		supervisor.limits.CleanupTimeout,
	)
	if !cleanupComplete {
		status = CleanupFailed
		cause = errors.Join(cause, waitErr)
	}
	inputErr := awaitInput(inputDone, supervisor.limits.CleanupTimeout)
	if inputErr != nil {
		if status == Completed {
			status = ExitFailed
		}
		cause = errors.Join(cause, inputErr)
	}
	streamDeadline := time.Now().Add(supervisor.limits.CleanupTimeout)
	out := awaitStream(stdoutReader, stdout, streamDeadline)
	diagnostics := awaitStream(stderrReader, stderr, streamDeadline)
	outcome := finishOutcome(process, status, cause, cleanupComplete, out, diagnostics)
	if err := process.close(); err != nil {
		outcome.Status = CleanupFailed
		outcome.CleanupComplete = false
		outcome.Err = errors.Join(outcome.Err, err)
	}
	return outcome
}

func awaitInput(input <-chan error, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-input:
		return err
	case <-timer.C:
		return errors.New("join worker input: cleanup deadline exceeded")
	}
}

func awaitProcess(
	ctx context.Context,
	timeout <-chan time.Time,
	waited <-chan error,
	overflow <-chan Status,
	input <-chan error,
) (Status, error) {
	for {
		select {
		case cause := <-waited:
			if cause != nil {
				return ExitFailed, cause
			}
			return Completed, nil
		case <-ctx.Done():
			return Cancelled, ctx.Err()
		case <-timeout:
			return TimedOut, context.DeadlineExceeded
		case status := <-overflow:
			return status, errStreamLimit
		case cause := <-input:
			if cause != nil {
				return ExitFailed, cause
			}
			input = nil
		}
	}
}

func finishOutcome(
	process *launchedProcess,
	status Status,
	cause error,
	cleanupComplete bool,
	out streamResult,
	diagnostics streamResult,
) Outcome {
	status, cause = applyStreamResult(status, cause, out, "output", OutputOverflow)
	status, cause = applyStreamResult(status, cause, diagnostics, "diagnostics", ErrorOverflow)
	status, exitCode, cause := readExit(process.info.Process, status, cause)
	return Outcome{
		Status:          status,
		Stdout:          out.data,
		Stderr:          diagnostics.data,
		ExitCode:        exitCode,
		Duration:        time.Since(process.started),
		CleanupComplete: cleanupComplete,
		Err:             cause,
	}
}

func applyStreamResult(
	status Status,
	cause error,
	result streamResult,
	name string,
	overflowStatus Status,
) (Status, error) {
	if errors.Is(result.err, errStreamLimit) && status == Completed {
		status = overflowStatus
	}
	if errors.Is(result.err, errStreamLimit) {
		return status, errors.Join(cause, result.err)
	}
	if result.err != nil {
		if status != CleanupFailed {
			status = ExitFailed
		}
		cause = errors.Join(cause, fmt.Errorf("read worker %s: %w", name, result.err))
	}
	return status, cause
}

func readExit(process windows.Handle, status Status, cause error) (Status, uint32, error) {
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process, &exitCode); err != nil {
		if status != CleanupFailed {
			status = ExitFailed
		}
		cause = errors.Join(cause, fmt.Errorf("read exit code: %w", err))
	} else if status == Completed && !protocolExit(exitCode) {
		status = ExitFailed
	}
	return status, exitCode, cause
}

func protocolExit(exitCode uint32) bool {
	switch exitCode {
	case 0, 2, 3:
		return true
	default:
		return false
	}
}

func createContainerName() (appContainer, error) {
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return appContainer{}, fmt.Errorf("generate AppContainer identity: %w", err)
	}
	return createContainer("celestia.worker." + hex.EncodeToString(random[:]))
}

func stageImage(folder, source string) (*os.File, [32]byte, string, error) {
	var hash [32]byte
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return nil, hash, "", fmt.Errorf("prepare AppContainer folder: %w", err)
	}
	sourceFile, err := openLocked(source, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, hash, "", fmt.Errorf("open worker: %w", err)
	}
	defer func() {
		_ = sourceFile.Close()
	}()
	target := filepath.Join(folder, "worker.exe")
	writer, err := openLocked(target, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.CREATE_NEW)
	if err != nil {
		return nil, hash, "", fmt.Errorf("create staged worker: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(writer, digest), sourceFile); err != nil {
		_ = writer.Close()
		return nil, hash, "", fmt.Errorf("stage worker: %w", err)
	}
	if err := writer.Sync(); err != nil {
		_ = writer.Close()
		return nil, hash, "", fmt.Errorf("flush staged worker: %w", err)
	}
	err = writer.Close()
	if err != nil {
		return nil, hash, "", fmt.Errorf("close staged worker: %w", err)
	}
	reader, err := openLocked(target, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, hash, "", fmt.Errorf("lock staged worker: %w", err)
	}
	copy(hash[:], digest.Sum(nil))
	stagedHash, err := hashFile(reader)
	if err != nil {
		_ = reader.Close()
		return nil, hash, "", err
	}
	if stagedHash != hash {
		_ = reader.Close()
		return nil, hash, "", errors.New("staged worker changed before execution lock")
	}
	return reader, hash, target, nil
}

func hashFile(file *os.File) ([32]byte, error) {
	var result [32]byte
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind staged worker: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return result, fmt.Errorf("hash staged worker: %w", err)
	}
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func openLocked(path string, access, disposition uint32) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer,
		access,
		windows.FILE_SHARE_READ,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func newPipes() (pipeSet, error) {
	var pipes pipeSet
	security := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	if err := windows.CreatePipe(&pipes.stdinRead, &pipes.stdinWrite, &security, 0); err != nil {
		return pipes, fmt.Errorf("create stdin pipe: %w", err)
	}
	if err := windows.CreatePipe(&pipes.stdoutRead, &pipes.stdoutWrite, &security, 0); err != nil {
		pipes.close()
		return pipes, fmt.Errorf("create stdout pipe: %w", err)
	}
	if err := windows.CreatePipe(&pipes.stderrRead, &pipes.stderrWrite, &security, 0); err != nil {
		pipes.close()
		return pipes, fmt.Errorf("create stderr pipe: %w", err)
	}
	for _, handle := range []windows.Handle{pipes.stdinWrite, pipes.stdoutRead, pipes.stderrRead} {
		if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			pipes.close()
			return pipes, fmt.Errorf("restrict parent pipe: %w", err)
		}
	}
	return pipes, nil
}

func startSuspended(
	container appContainer,
	imagePath string,
	pipes pipeSet,
) (windows.ProcessInformation, error) {
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("create process attributes: %w", err)
	}
	defer attributes.Delete()
	capabilities := securityCapabilities{appContainerSID: container.sid}
	if err := attributes.Update(
		securityCapabilitiesAttribute,
		unsafe.Pointer(&capabilities), // #nosec G103 -- Win32 reads the typed capability structure.
		unsafe.Sizeof(capabilities),
	); err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("set AppContainer: %w", err)
	}
	handles := []windows.Handle{pipes.stdinRead, pipes.stdoutWrite, pipes.stderrWrite}
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]), // #nosec G103 -- Win32 reads the contiguous handle list.
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("set inherited handles: %w", err)
	}
	image, _ := windows.UTF16PtrFromString(imagePath)
	command, _ := windows.UTF16PtrFromString(windows.EscapeArg(imagePath))
	directory, _ := windows.UTF16PtrFromString(container.folder)
	environment, err := environmentBlock(container.folder)
	if err != nil {
		return windows.ProcessInformation{}, err
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     startfUseStdHandles,
			StdInput:  pipes.stdinRead,
			StdOutput: pipes.stdoutWrite,
			StdErr:    pipes.stderrWrite,
		},
		ProcThreadAttributeList: attributes.List(),
	}
	var info windows.ProcessInformation
	err = windows.CreateProcess(
		image,
		command,
		nil,
		nil,
		true,
		extendedStartupInfoPresent|createSuspended|createNoWindow|createUnicodeEnvironment,
		&environment[0],
		directory,
		&startup.StartupInfo,
		&info,
	)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("start AppContainer worker: %w", err)
	}
	runtime.KeepAlive(capabilities)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(environment)
	return info, nil
}

func environmentBlock(folder string) ([]uint16, error) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return nil, fmt.Errorf("%w: SystemRoot is unavailable", ErrInvalid)
	}
	temp := filepath.Join(folder, "Temp")
	if err := os.MkdirAll(temp, 0o700); err != nil {
		return nil, fmt.Errorf("prepare worker temporary directory: %w", err)
	}
	values := []string{
		"LOCALAPPDATA=" + folder,
		"SystemRoot=" + systemRoot,
		"TEMP=" + temp,
		"TMP=" + temp,
		"WINDIR=" + systemRoot,
	}
	var block []uint16
	for _, value := range values {
		encoded, err := windows.UTF16FromString(value)
		if err != nil {
			return nil, fmt.Errorf("encode worker environment: %w", err)
		}
		block = append(block, encoded...)
	}
	return append(block, 0), nil
}

func writeFrame(handle windows.Handle, frame []byte) error {
	file := os.NewFile(uintptr(handle), "worker-stdin")
	if file == nil {
		return errors.New("create worker stdin")
	}
	written, writeErr := io.Copy(file, bytes.NewReader(frame))
	if writeErr == nil && written != int64(len(frame)) {
		writeErr = io.ErrShortWrite
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("write worker frame: %w", err)
	}
	return nil
}

func waitCleanup(process, job windows.Handle, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	wait := waitMilliseconds(timeout)
	event, err := windows.WaitForSingleObject(process, wait)
	if err != nil {
		return false, fmt.Errorf("wait for worker cleanup: %w", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return false, errors.New("worker cleanup deadline exceeded")
	}
	if event != windows.WAIT_OBJECT_0 {
		return false, fmt.Errorf("unexpected worker wait result: %d", event)
	}
	for {
		empty, err := jobEmpty(job)
		if err != nil {
			return false, err
		}
		if empty {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, errors.New("process tree cleanup deadline exceeded")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitMilliseconds(timeout time.Duration) uint32 {
	milliseconds := uint64(timeout / time.Millisecond) // #nosec G115 -- valid limits require a positive duration.
	if milliseconds >= uint64(^uint32(0)-1) {
		return ^uint32(0) - 1
	}
	return uint32(milliseconds)
}

func jobEmpty(job windows.Handle) (bool, error) {
	var accounting jobAccounting
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)), // #nosec G103 -- Win32 writes the typed accounting structure.
		uint32(unsafe.Sizeof(accounting)),
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("query process tree: %w", err)
	}
	return accounting.activeProcesses == 0, nil
}

func failedOutcome(status Status, started time.Time, err error) Outcome {
	return Outcome{
		Status:   status,
		Duration: time.Since(started),
		Err:      err,
	}
}

func (process *launchedProcess) close() error {
	process.pipes.close()
	var closeErr error
	if err := windows.CloseHandle(process.info.Process); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker process: %w", err))
	}
	if err := windows.CloseHandle(process.job); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker job: %w", err))
	}
	if err := process.image.Close(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker image: %w", err))
	}
	if err := process.container.close(); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	return closeErr
}

func (pipes *pipeSet) closeChildEnds() {
	closeHandle(&pipes.stdinRead)
	closeHandle(&pipes.stdoutWrite)
	closeHandle(&pipes.stderrWrite)
}

func (pipes *pipeSet) close() {
	closeHandle(&pipes.stdinRead)
	closeHandle(&pipes.stdinWrite)
	closeHandle(&pipes.stdoutRead)
	closeHandle(&pipes.stdoutWrite)
	closeHandle(&pipes.stderrRead)
	closeHandle(&pipes.stderrWrite)
}

func closeHandle(handle *windows.Handle) {
	if *handle != 0 {
		_ = windows.CloseHandle(*handle)
		*handle = 0
	}
}
