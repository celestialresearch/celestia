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
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobActiveProcessZero = 4
	joinTimeout          = 10 * time.Second
	descendantGrace      = time.Second
	jobPollInterval      = 50 * time.Millisecond
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

type jobProcessIDList struct {
	assigned uint32
	count    uint32
	ids      [1]uintptr
}

type jobOwner struct {
	handle       windows.Handle
	terminate    sync.Once
	terminateErr error
}

type suspendedCargoStarter func(string, Request) (windows.ProcessInformation, error)

type treeWaiter func(context.Context, windows.Handle, windows.Handle, time.Duration, bool) (bool, error)

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
	return buildWithStarterAndWaiter(ctx, request, executable, start, waitJobEmpty)
}

func buildWithStarterAndWaiter(
	ctx context.Context,
	request Request,
	executable string,
	start suspendedCargoStarter,
	wait treeWaiter,
) (result error) {
	deadline, err := buildDeadline(ctx)
	if err != nil {
		return err
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
		return finishStoppedBuild(ctx, job, port, process.Process, err)
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return finishStoppedBuild(ctx, job, port, process.Process, fmt.Errorf("resume Cargo: %w", err))
	}

	return awaitBuild(ctx, deadline, job, port, process.Process, wait)
}

func buildDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, errors.New("run Cargo: missing context")
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, fmt.Errorf("run Cargo: %w", err)
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		return time.Time{}, errors.New("run Cargo: context lacks deadline")
	}
	if time.Until(deadline) <= 0 {
		return time.Time{}, fmt.Errorf("run Cargo: %w", context.DeadlineExceeded)
	}
	return deadline, nil
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
	deadline time.Time,
	job *jobOwner,
	port, process windows.Handle,
	wait treeWaiter,
) (result error) {
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return finishStoppedBuild(ctx, job, port, process, fmt.Errorf("create Cargo cancellation event: %w", err))
	}
	defer func() {
		result = errors.Join(result, closeHandle("close Cargo cancellation event", cancelEvent))
	}()
	signal := make(chan error, 1)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(callbackDone)
		signal <- windows.SetEvent(cancelEvent)
	})
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return finishStoppedBuild(ctx, job, port, process, context.DeadlineExceeded)
	}
	event, err := windows.WaitForMultipleObjects(
		[]windows.Handle{process, cancelEvent}, false, waitMilliseconds(remaining),
	)
	if err := stopCancellation(stop, callbackDone, signal); err != nil {
		return finishStoppedBuild(ctx, job, port, process, fmt.Errorf("signal Cargo cancellation: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return finishStoppedBuild(ctx, job, port, process, err)
	}
	if err != nil {
		return finishStoppedBuild(ctx, job, port, process, fmt.Errorf("wait for Cargo: %w", err))
	}
	if cause := waitCause(ctx, event); cause != nil {
		return finishStoppedBuild(ctx, job, port, process, cause)
	}
	if event != windows.WAIT_OBJECT_0 {
		return finishStoppedBuild(ctx, job, port, process, fmt.Errorf("unexpected Cargo wait result: %d", event))
	}
	if err := joinTree(ctx, job, port, process, true, wait); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return finishStoppedBuild(ctx, job, port, process, err)
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

func waitCause(ctx context.Context, event uint32) error {
	switch event {
	case windows.WAIT_OBJECT_0 + 1:
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.Canceled
	case uint32(windows.WAIT_TIMEOUT):
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func stopCancellation(stop func() bool, callbackDone <-chan struct{}, signal <-chan error) error {
	if stop() {
		return nil
	}
	<-callbackDone
	return <-signal
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
	ctx context.Context,
	job *jobOwner,
	port, process windows.Handle,
	cause error,
) error {
	return errors.Join(cause, joinTree(ctx, job, port, process, false, waitJobEmpty))
}

func (job *jobOwner) stop() error {
	job.terminate.Do(func() {
		job.terminateErr = windows.TerminateJobObject(job.handle, 1)
	})
	return job.terminateErr
}

func joinTree(
	ctx context.Context,
	job *jobOwner,
	port, process windows.Handle,
	allowGrace bool,
	wait treeWaiter,
) error {
	deadline := time.Now().Add(joinTimeout)
	if !allowGrace {
		return terminateAndJoin(ctx, job, port, process, deadline, nil, nil, nil, wait)
	}
	if err := waitExitedUntil(process, deadline); err != nil {
		return terminateAndJoin(ctx, job, port, process, deadline, err, nil, nil, wait)
	}
	handles, captureErr := jobProcessHandles(job.handle)
	graceDeadline := time.Now().Add(descendantGrace)
	if deadline.Before(graceDeadline) {
		graceDeadline = deadline
	}
	empty, err := wait(ctx, job.handle, port, time.Until(graceDeadline), false)
	if err != nil {
		return terminateAndJoin(ctx, job, port, process, deadline, errors.Join(err, errors.New("observe Cargo process tree")), handles, captureErr, wait)
	}
	if empty {
		return errors.Join(waitProcessHandles(handles, deadline), closeProcessHandles(handles))
	}
	return terminateAndJoin(ctx, job, port, process, deadline, errors.New("cargo exited with a running descendant"), handles, captureErr, wait)
}

func terminateAndJoin(
	ctx context.Context,
	job *jobOwner,
	port windows.Handle,
	process windows.Handle,
	deadline time.Time,
	cause error,
	handles []windows.Handle,
	captureErr error,
	wait treeWaiter,
) (result error) {
	if cause == nil {
		cause = ctx.Err()
	}
	defer func() {
		result = errors.Join(result, closeProcessHandles(handles))
	}()
	stopErr := job.stop()
	processErr := waitExitedUntil(process, deadline)
	if handles == nil && captureErr == nil {
		handles, captureErr = jobProcessHandles(job.handle)
	}
	empty, observeErr := wait(context.WithoutCancel(ctx), job.handle, port, time.Until(deadline), true)
	afterStop, afterStopErr := jobProcessHandles(job.handle)
	handles = append(handles, afterStop...)
	joinErr := waitProcessHandles(handles, deadline)
	if observeErr == nil && empty {
		return errors.Join(cause, stopErr, processErr, captureErr, afterStopErr, joinErr)
	}
	if observeErr != nil {
		return errors.Join(cause, stopErr, processErr, captureErr, observeErr, afterStopErr, joinErr)
	}
	return errors.Join(cause, stopErr, processErr, captureErr, afterStopErr, joinErr, errors.New("cargo process tree cleanup deadline exceeded"))
}

func waitJobEmpty(
	ctx context.Context,
	job, port windows.Handle,
	timeout time.Duration,
	requireSignal bool,
) (bool, error) {
	if !requireSignal {
		empty, err := jobEmpty(job)
		if err != nil || empty {
			return empty, err
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		empty, retry, err := observeJob(ctx, job, port, deadline)
		if err != nil {
			return false, err
		}
		if empty {
			return true, nil
		}
		if !retry {
			return false, nil
		}
	}
}

func observeJob(
	ctx context.Context,
	job, port windows.Handle,
	deadline time.Time,
) (bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false, false, nil
	}
	message, timedOut, err := waitJobMessage(port, remaining)
	if err != nil {
		return false, false, err
	}
	if timedOut || message != jobActiveProcessZero {
		return false, time.Until(deadline) > 0, nil
	}
	empty, err := jobEmpty(job)
	return empty, !empty, err
}

func waitJobMessage(port windows.Handle, remaining time.Duration) (uint32, bool, error) {
	if remaining > jobPollInterval {
		remaining = jobPollInterval
	}
	var message uint32
	var key uintptr
	var overlapped *windows.Overlapped
	err := windows.GetQueuedCompletionStatus(port, &message, &key, &overlapped, waitMilliseconds(remaining))
	if errors.Is(err, windows.ERROR_TIMEOUT) || errors.Is(err, syscall.Errno(windows.WAIT_TIMEOUT)) {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("wait for Cargo process tree: %w", err)
	}
	return message, false, nil
}

func jobEmpty(job windows.Handle) (bool, error) {
	active, err := jobActive(job)
	return !active, err
}

func waitProcessHandles(handles []windows.Handle, deadline time.Time) error {
	for _, handle := range handles {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("cargo process tree cleanup deadline exceeded")
		}
		event, err := windows.WaitForSingleObject(handle, waitMilliseconds(remaining))
		if err != nil {
			return fmt.Errorf("wait for terminated Cargo process tree: %w", err)
		}
		if event != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("unexpected terminated Cargo process result: %d", event)
		}
	}
	return nil
}

func waitExitedUntil(process windows.Handle, deadline time.Time) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return errors.New("cargo process tree cleanup deadline exceeded")
	}
	event, err := windows.WaitForSingleObject(process, waitMilliseconds(remaining))
	if err != nil {
		return fmt.Errorf("wait for Cargo process: %w", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return errors.New("cargo process tree cleanup deadline exceeded")
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected Cargo process result: %d", event)
	}
	return nil
}

func jobProcessHandles(job windows.Handle) ([]windows.Handle, error) {
	size, err := nextProcessListSize(0, 16, 0)
	if err != nil {
		return nil, err
	}
	for {
		buffer := make([]byte, size)
		err := windows.QueryInformationJobObject(
			job,
			windows.JobObjectBasicProcessIdList,
			uintptr(nativePointer(&buffer[0])),
			size,
			nil,
		)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("query terminated Cargo process tree: %w", err)
		}
		list := (*jobProcessIDList)(nativePointer(&buffer[0]))
		nextSize, sizeErr := nextProcessListSize(size, list.assigned, list.count)
		if sizeErr != nil {
			return nil, sizeErr
		}
		if nextSize != 0 {
			size = nextSize
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("query terminated Cargo process tree: %w", err)
		}
		available := (size - uint32(unsafe.Offsetof(jobProcessIDList{}.ids))) / uint32(unsafe.Sizeof(uintptr(0)))
		if list.count > available {
			return nil, errors.New("query terminated Cargo process tree: invalid process count")
		}
		return openJobProcesses(processIDs(list))
	}
}

func openJobProcesses(ids []uintptr) ([]windows.Handle, error) {
	handles := make([]windows.Handle, 0, len(ids))
	for _, id := range ids {
		if id > uintptr(^uint32(0)) {
			return nil, errors.New("query terminated Cargo process tree: invalid process identity")
		}
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(id))
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			continue
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("open terminated Cargo process: %w", err), closeProcessHandles(handles))
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func nextProcessListSize(current, assigned, count uint32) (uint32, error) {
	if count > assigned {
		return 0, errors.New("query terminated Cargo process tree: invalid process count")
	}
	if count == assigned && current != 0 {
		return 0, nil
	}
	required := uint64(unsafe.Offsetof(jobProcessIDList{}.ids)) + uint64(assigned)*uint64(unsafe.Sizeof(uintptr(0)))
	if required > 1<<20 || required > uint64(^uint32(0)) {
		return 0, errors.New("query terminated Cargo process tree: process list is too large")
	}
	if uint32(required) <= current {
		return 0, errors.New("query terminated Cargo process tree: incomplete process list")
	}
	return uint32(required), nil
}

func processIDs(list *jobProcessIDList) []uintptr {
	return unsafe.Slice(&list.ids[0], list.count) // #nosec G103 -- Win32 supplies the bounded variable-length process list.
}

func closeProcessHandles(handles []windows.Handle) error {
	var result error
	for _, handle := range handles {
		result = errors.Join(result, closeHandle("close terminated Cargo process", handle))
	}
	return result
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
	return waitExitedUntil(process, time.Now().Add(joinTimeout))
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
