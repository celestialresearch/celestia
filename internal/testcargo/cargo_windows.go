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

package testcargo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobActiveProcessZero = 4
	joinTimeout          = 10 * time.Second
)

// Request describes one Cargo build owned by a Windows test.
type Request struct {
	Arguments   []string
	Directory   string
	Environment []string
}

type jobAccounting struct {
	_               int64
	_               int64
	_               int64
	_               int64
	_               uint32
	_               uint32
	activeProcesses uint32
	_               uint32
}

type jobCompletionPort struct {
	_    uintptr
	port windows.Handle
}

type jobOwner struct {
	handle       windows.Handle
	terminate    sync.Once
	terminateErr error
}

type suspendedCargoStarter func(string, Request) (windows.ProcessInformation, error)

// Build starts one Cargo process suspended, owns its process tree and waits
// for that tree to end before returning.
func Build(ctx context.Context, request Request) error {
	return buildWithStarter(ctx, request, "cargo", startSuspended)
}

func buildWithExecutable(ctx context.Context, request Request, executable string) (result error) {
	return buildWithStarter(ctx, request, executable, startSuspended)
}

func buildWithStarter(
	ctx context.Context,
	request Request,
	executable string,
	start suspendedCargoStarter,
) (result error) {
	if ctx == nil {
		return errors.New("run Cargo: missing context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("run Cargo: %w", err)
	}
	if executable == "" {
		return errors.New("run Cargo: missing executable")
	}
	if err := validateRequest(request); err != nil {
		return err
	}
	job, port, err := newJobOwner()
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, closeHandle("close Cargo completion port", port))
	}()
	defer func() {
		result = errors.Join(result, closeHandle("close Cargo job", job.handle))
	}()

	process, err := start(executable, request)
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, closeHandle("close Cargo thread", process.Thread))
	}()
	defer func() {
		result = errors.Join(result, closeHandle("close Cargo process", process.Process))
	}()
	if err := ctx.Err(); err != nil {
		return finishUnassignedBuild(process.Process, err)
	}
	if err := windows.AssignProcessToJobObject(job.handle, process.Process); err != nil {
		return finishUnassignedBuild(process.Process, fmt.Errorf("assign Cargo job: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return finishStoppedBuild(job, port, process.Process, err)
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return finishStoppedBuild(job, port, process.Process, fmt.Errorf("resume Cargo: %w", err))
	}

	return awaitBuild(ctx, job, port, process.Process)
}

func validateRequest(request Request) error {
	if len(request.Arguments) == 0 {
		return errors.New("run Cargo: missing arguments")
	}
	if !filepath.IsAbs(request.Directory) {
		return errors.New("run Cargo: directory is not absolute")
	}
	for _, argument := range request.Arguments {
		if strings.IndexByte(argument, 0) >= 0 {
			return errors.New("run Cargo: argument contains NUL")
		}
	}
	_, err := environmentBlock(request.Environment)
	return err
}

func newJobOwner() (*jobOwner, windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create Cargo job: %w", err)
	}
	owner := &jobOwner{handle: job}
	if err := configureJob(job); err != nil {
		return nil, 0, errors.Join(err, closeHandle("close Cargo job", job))
	}
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, 0, errors.Join(
			fmt.Errorf("create Cargo completion port: %w", err), closeHandle("close Cargo job", job),
		)
	}
	association := jobCompletionPort{port: port}
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectAssociateCompletionPortInformation,
		uintptr(nativePointer(&association)),
		uint32(unsafe.Sizeof(association)),
	)
	if err != nil {
		return nil, 0, errors.Join(
			fmt.Errorf("associate Cargo completion port: %w", err),
			closeHandle("close Cargo completion port", port),
			closeHandle("close Cargo job", job),
		)
	}
	return owner, port, nil
}

func configureJob(job windows.Handle) error {
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(nativePointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	)
	if err != nil {
		return fmt.Errorf("configure Cargo job: %w", err)
	}
	return nil
}

func startSuspended(executable string, request Request) (process windows.ProcessInformation, result error) {
	path, err := exec.LookPath(executable)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("find Cargo executable: %w", err)
	}
	application, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("encode Cargo executable: %w", err)
	}
	line, err := windows.UTF16PtrFromString(commandLine(path, request.Arguments))
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("encode Cargo command line: %w", err)
	}
	directory, err := windows.UTF16PtrFromString(request.Directory)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("encode Cargo directory: %w", err)
	}
	environment, err := environmentBlock(request.Environment)
	if err != nil {
		return windows.ProcessInformation{}, err
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("create Cargo attributes: %w", err)
	}
	defer attributes.Delete()
	handles, closeHandles, err := inheritedStandardHandles()
	if err != nil {
		return windows.ProcessInformation{}, err
	}
	defer func() {
		closeErr := closeHandles()
		if result != nil {
			result = errors.Join(result, closeErr)
			return
		}
		if closeErr != nil {
			result = discardStartedProcess(process, closeErr)
			process = windows.ProcessInformation{}
		}
	}()
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		nativePointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("set Cargo inherited handles: %w", err)
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  handles[0],
			StdOutput: handles[1],
			StdErr:    handles[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	result = windows.CreateProcess(
		application,
		line,
		nil,
		nil,
		true,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT|
			windows.EXTENDED_STARTUPINFO_PRESENT,
		&environment[0],
		directory,
		&startup.StartupInfo,
		&process,
	)
	if result != nil {
		return windows.ProcessInformation{}, fmt.Errorf("start Cargo suspended: %w", result)
	}
	return process, nil
}

func inheritedStandardHandles() ([]windows.Handle, func() error, error) {
	sources := []windows.Handle{
		windows.Handle(os.Stdin.Fd()),
		windows.Handle(os.Stdout.Fd()),
		windows.Handle(os.Stderr.Fd()),
	}
	handles := make([]windows.Handle, 0, len(sources))
	closeHandles := func() error {
		var result error
		for _, handle := range handles {
			result = errors.Join(result, closeHandle("close Cargo inherited handle", handle))
		}
		return result
	}
	for _, source := range sources {
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(
			windows.CurrentProcess(), source, windows.CurrentProcess(), &duplicate,
			0, true, windows.DUPLICATE_SAME_ACCESS,
		); err != nil {
			return nil, nil, errors.Join(
				fmt.Errorf("duplicate Cargo standard handle: %w", err), closeHandles(),
			)
		}
		handles = append(handles, duplicate)
	}
	return handles, closeHandles, nil
}

func commandLine(path string, arguments []string) string {
	values := make([]string, 0, len(arguments)+1)
	values = append(values, windows.EscapeArg(path))
	for _, argument := range arguments {
		values = append(values, windows.EscapeArg(argument))
	}
	return strings.Join(values, " ")
}

func environmentBlock(environment []string) ([]uint16, error) {
	values := environment
	if values == nil {
		values = os.Environ()
	}
	values = append([]string(nil), values...)
	if len(values) == 0 {
		return []uint16{0, 0}, nil
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key, valid := environmentKey(value)
		if !valid || strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("encode Cargo environment: invalid entry")
		}
		key = strings.ToUpper(key)
		if _, exists := seen[key]; exists {
			return nil, errors.New("encode Cargo environment: duplicate key")
		}
		seen[key] = struct{}{}
	}
	sort.Slice(values, func(left, right int) bool {
		leftKey, _ := environmentKey(values[left])
		rightKey, _ := environmentKey(values[right])
		return strings.ToUpper(leftKey) < strings.ToUpper(rightKey)
	})
	block := make([]uint16, 0, len(values)*32)
	for _, value := range values {
		encoded, err := windows.UTF16FromString(value)
		if err != nil {
			return nil, fmt.Errorf("encode Cargo environment: %w", err)
		}
		block = append(block, encoded...)
	}
	return append(block, 0), nil
}

func environmentKey(value string) (string, bool) {
	if strings.HasPrefix(value, "=") {
		if index := strings.Index(value[1:], "="); index >= 0 {
			return value[:index+1], index > 0
		}
		return "", false
	}
	key, _, _ := strings.Cut(value, "=")
	return key, key != "" && len(key) < len(value)
}

func awaitBuild(
	ctx context.Context,
	job *jobOwner,
	port, process windows.Handle,
) (result error) {
	cancelled := atomic.Bool{}
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return finishStoppedBuild(job, port, process, fmt.Errorf("create Cargo cancellation event: %w", err))
	}
	defer func() {
		result = errors.Join(result, closeHandle("close Cargo cancellation event", cancelEvent))
	}()
	signal := make(chan error, 1)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(callbackDone)
		cancelled.Store(true)
		signal <- windows.SetEvent(cancelEvent)
	})
	event, err := windows.WaitForMultipleObjects(
		[]windows.Handle{process, cancelEvent}, false, windows.INFINITE,
	)
	if !stop() {
		<-callbackDone
		cancelled.Store(true)
		if signalErr := <-signal; signalErr != nil {
			return finishStoppedBuild(job, port, process, fmt.Errorf("signal Cargo cancellation: %w", signalErr))
		}
	}
	if err != nil {
		return finishStoppedBuild(job, port, process, fmt.Errorf("wait for Cargo: %w", err))
	}
	if event == windows.WAIT_OBJECT_0+1 || cancelled.Load() {
		cause := ctx.Err()
		if cause == nil {
			cause = context.Canceled
		}
		return finishStoppedBuild(job, port, process, cause)
	}
	if event != windows.WAIT_OBJECT_0 {
		return finishStoppedBuild(job, port, process, fmt.Errorf("unexpected Cargo wait result: %d", event))
	}
	if err := joinTree(job, port, process, true); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(process, &code); err != nil {
		return fmt.Errorf("read Cargo exit code: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("cargo exited with status %d", code)
	}
	return nil
}

func finishUnassignedBuild(process windows.Handle, cause error) error {
	terminateErr := windows.TerminateProcess(process, 1)
	waitErr := waitExited(process)
	return errors.Join(cause, terminateErr, waitErr)
}

func discardStartedProcess(process windows.ProcessInformation, cause error) error {
	return errors.Join(
		finishUnassignedBuild(process.Process, cause),
		closeHandle("close Cargo thread", process.Thread),
		closeHandle("close Cargo process", process.Process),
	)
}

func finishStoppedBuild(
	job *jobOwner,
	port, process windows.Handle,
	cause error,
) error {
	return errors.Join(cause, job.stop(), joinTree(job, port, process, false))
}

func (job *jobOwner) stop() error {
	job.terminate.Do(func() {
		job.terminateErr = windows.TerminateJobObject(job.handle, 1)
	})
	return job.terminateErr
}

func joinTree(job *jobOwner, port, process windows.Handle, allowGrace bool) error {
	event, err := windows.WaitForSingleObject(process, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wait for Cargo process: %w", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected Cargo process result: %d", event)
	}
	if allowGrace {
		empty, err := waitJobEmpty(job.handle, port, joinTimeout, false)
		if err != nil {
			return err
		}
		if empty {
			return nil
		}
	}
	if err := job.stop(); err != nil {
		return fmt.Errorf("terminate Cargo process tree: %w", err)
	}
	empty, err := waitJobEmpty(job.handle, port, joinTimeout, true)
	if err != nil {
		return err
	}
	if !empty {
		return errors.New("cargo process tree cleanup deadline exceeded")
	}
	if allowGrace {
		return errors.New("cargo exited with a running descendant")
	}
	return nil
}

func waitJobEmpty(job, port windows.Handle, timeout time.Duration, requireSignal bool) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		if !requireSignal {
			active, err := jobActive(job)
			if err != nil {
				return false, err
			}
			if !active {
				return true, nil
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		var message uint32
		var key uintptr
		var overlapped *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(
			port, &message, &key, &overlapped, waitMilliseconds(remaining),
		); err != nil {
			if errors.Is(err, windows.ERROR_TIMEOUT) || errors.Is(err, syscall.Errno(windows.WAIT_TIMEOUT)) {
				return false, nil
			}
			return false, fmt.Errorf("wait for Cargo process tree: %w", err)
		}
		if message == jobActiveProcessZero {
			active, err := jobActive(job)
			if err != nil {
				return false, err
			}
			if !active {
				return true, nil
			}
		}
	}
}

func jobActive(job windows.Handle) (bool, error) {
	var accounting jobAccounting
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(nativePointer(&accounting)),
		uint32(unsafe.Sizeof(accounting)),
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("query Cargo process tree: %w", err)
	}
	return accounting.activeProcesses != 0, nil
}

func waitExited(process windows.Handle) error {
	event, err := windows.WaitForSingleObject(process, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wait for Cargo process: %w", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected Cargo process result: %d", event)
	}
	return nil
}

func closeHandle(operation string, handle windows.Handle) error {
	if err := windows.CloseHandle(handle); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func waitMilliseconds(timeout time.Duration) uint32 {
	if timeout <= 0 {
		return 0
	}
	milliseconds := timeout / time.Millisecond
	if timeout%time.Millisecond != 0 {
		milliseconds++
	}
	if milliseconds >= time.Duration(^uint32(0)-1) {
		return ^uint32(0) - 1
	}
	return uint32(milliseconds)
}
