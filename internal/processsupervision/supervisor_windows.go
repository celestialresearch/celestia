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

package processsupervision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
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
	data       []byte
	err        error
	cleanupErr error
}

type inputResult struct {
	err        error
	cleanupErr error
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

type launchPreparationOperations struct {
	createContainer func() (appContainer, error)
	stageImage      func(string, string) (*os.File, [32]byte, string, bool, error)
	newPipes        func() (pipeSet, bool, error)
	createJob       func(Limits) (windows.Handle, bool, error)
}

type processStartOperations struct {
	start      func(appContainer, string, pipeSet) (windows.ProcessInformation, error)
	assign     func(windows.Handle, windows.Handle) error
	closePipes func(*pipeSet) error
	resume     func(windows.Handle) (uint32, error)
}

type suspendedProcessOperations struct {
	newAttributes func(uint32) (*windows.ProcThreadAttributeListContainer, error)
	update        func(*windows.ProcThreadAttributeListContainer, uintptr, unsafe.Pointer, uintptr) error
	encode        func(string) (*uint16, error)
	environment   func(string) ([]uint16, error)
	create        func(
		*uint16,
		*uint16,
		*windows.SecurityAttributes,
		*windows.SecurityAttributes,
		bool,
		uint32,
		*uint16,
		*uint16,
		*windows.StartupInfo,
		*windows.ProcessInformation,
	) error
}

type startupStopOperations struct {
	closeChild       func(*pipeSet) error
	terminateJob     func(windows.Handle, uint32) error
	terminateProcess func(windows.Handle, uint32) error
	wait             func(windows.Handle, windows.Handle, time.Duration) (bool, error)
	closeHandle      func(windows.Handle) error
}

type supervisorCreationOperations struct {
	open  func(string) (*os.File, error)
	hash  func(*os.File) ([32]byte, error)
	close func(*os.File) error
}

func defaultLaunchPreparationOperations() launchPreparationOperations {
	return launchPreparationOperations{
		createContainer: createContainerName,
		stageImage:      stageImage,
		newPipes:        newPipes,
		createJob:       createJob,
	}
}

func defaultProcessStartOperations() processStartOperations {
	return processStartOperations{
		start:      startSuspended,
		assign:     windows.AssignProcessToJobObject,
		closePipes: (*pipeSet).closeChildEnds,
		resume:     windows.ResumeThread,
	}
}

func defaultSuspendedProcessOperations() suspendedProcessOperations {
	return suspendedProcessOperations{
		newAttributes: windows.NewProcThreadAttributeList,
		update: func(
			attributes *windows.ProcThreadAttributeListContainer,
			attribute uintptr,
			value unsafe.Pointer,
			size uintptr,
		) error {
			return attributes.Update(attribute, value, size)
		},
		encode:      windows.UTF16PtrFromString,
		environment: environmentBlock,
		create:      windows.CreateProcess,
	}
}

func defaultStartupStopOperations() startupStopOperations {
	return startupStopOperations{
		closeChild:       (*pipeSet).closeChildEnds,
		terminateJob:     windows.TerminateJobObject,
		terminateProcess: windows.TerminateProcess,
		wait:             waitCleanup,
		closeHandle:      windows.CloseHandle,
	}
}

func defaultSupervisorCreationOperations() supervisorCreationOperations {
	return supervisorCreationOperations{
		open: openLocalImage,
		hash: hashFile,
		close: func(file *os.File) error {
			return file.Close()
		},
	}
}

func newSupervisor(workerPath string, limits Limits) (*Supervisor, error) {
	return newSupervisorWith(
		workerPath,
		limits,
		defaultSupervisorCreationOperations(),
	)
}

func newSupervisorWith(
	workerPath string,
	limits Limits,
	operations supervisorCreationOperations,
) (*Supervisor, error) {
	if !validWorkerPath(workerPath) || !validLimits(limits) {
		return nil, fmt.Errorf("%w: worker path or limits", ErrInvalid)
	}
	cleanPath := filepath.Clean(workerPath)
	worker, err := operations.open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open worker: %w", ErrInvalid, err)
	}
	hash, hashErr := operations.hash(worker)
	closeErr := operations.close(worker)
	if err := errors.Join(hashErr, closeErr); err != nil {
		return nil, fmt.Errorf("%w: measure worker: %w", ErrInvalid, err)
	}
	return &Supervisor{
		workerPath: cleanPath,
		workerHash: hash,
		limits:     limits,
	}, nil
}

func validWorkerPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	volume := filepath.VolumeName(path)
	return len(volume) == 2 &&
		((volume[0] >= 'A' && volume[0] <= 'Z') ||
			(volume[0] >= 'a' && volume[0] <= 'z')) &&
		volume[1] == ':'
}

func validLimits(limits Limits) bool {
	return validStreamLimit(limits.InputBytes) &&
		validStreamLimit(limits.OutputBytes) &&
		validStreamLimit(limits.ErrorBytes) &&
		limits.MemoryBytes > 0 &&
		limits.Processes > 0 &&
		limits.StartupTimeout > 0 &&
		limits.Timeout >= 100*time.Nanosecond &&
		limits.CleanupTimeout > 0
}

func validStreamLimit(limit int) bool {
	return limit > 0 && limit < math.MaxInt
}

func (supervisor *Supervisor) run(
	ctx context.Context,
	frame []byte,
	startDeadline time.Time,
) Outcome {
	started := time.Now()
	if ctx == nil ||
		startDeadline.IsZero() ||
		len(frame) == 0 ||
		len(frame) > supervisor.limits.InputBytes {
		outcome := failedOutcome(StartFailed, started, fmt.Errorf("%w: context or frame", ErrInvalid))
		outcome.WorkerSHA256 = supervisor.workerHash
		outcome.CleanupComplete = true
		return outcome
	}
	select {
	case <-ctx.Done():
		outcome := failedOutcome(Cancelled, started, ctx.Err())
		outcome.WorkerSHA256 = supervisor.workerHash
		outcome.CleanupComplete = true
		return outcome
	default:
	}
	if err := checkStartupDeadline(startDeadline); err != nil {
		outcome := failedOutcome(StartFailed, started, err)
		outcome.WorkerSHA256 = supervisor.workerHash
		outcome.CleanupComplete = true
		return outcome
	}
	startupDeadline := earliestDeadline(
		startDeadline,
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
	process, hash, cleanupComplete, err := supervisor.launch(ctx, startupDeadline)
	if err != nil {
		outcome := failedLaunchOutcome(started, cleanupComplete, err)
		outcome.WorkerSHA256 = supervisor.workerHash
		if hash != ([32]byte{}) {
			outcome.WorkerSHA256 = hash
		}
		outcome.CleanupComplete = cleanupComplete
		return outcome
	}
	remaining := executionRemaining(
		process.started,
		supervisor.limits.Timeout,
		time.Now(),
	)
	outcome := supervisor.observe(ctx, process, frame, remaining)
	outcome.WorkerSHA256 = hash
	return outcome
}

func (supervisor *Supervisor) launch(
	ctx context.Context,
	startupDeadline time.Time,
) (*launchedProcess, [32]byte, bool, error) {
	resources, cleanupComplete, err := supervisor.prepareLaunch(ctx, startupDeadline)
	if err != nil {
		return nil, [32]byte{}, cleanupComplete, err
	}
	process, cleanupComplete, err := resources.start(ctx, startupDeadline)
	if err != nil {
		closeErr := resources.close()
		return nil,
			resources.imageHash,
			cleanupComplete && closeErr == nil,
			errors.Join(err, closeErr)
	}
	return process, resources.imageHash, true, nil
}

func (supervisor *Supervisor) prepareLaunch(
	ctx context.Context,
	startupDeadline time.Time,
) (*launchResources, bool, error) {
	return supervisor.prepareLaunchWith(ctx, startupDeadline, defaultLaunchPreparationOperations())
}

func (supervisor *Supervisor) prepareLaunchWith(
	ctx context.Context,
	startupDeadline time.Time,
	operations launchPreparationOperations,
) (*launchResources, bool, error) {
	container, err := operations.createContainer()
	if err != nil {
		if container.name != "" {
			cleanupErr := container.close()
			return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
		}
		return nil, true, err
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := container.close()
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	image, hash, imagePath, imageCleanupComplete, err := operations.stageImage(
		container.folder,
		supervisor.workerPath,
	)
	if err != nil {
		cleanupErr := container.close()
		return nil,
			cleanupSucceeded(imageCleanupComplete, cleanupErr),
			errors.Join(err, cleanupErr)
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := errors.Join(image.Close(), container.close())
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	if hash != supervisor.workerHash {
		cleanupErr := errors.Join(image.Close(), container.close())
		return nil,
			cleanupErr == nil,
			errors.Join(errors.New("configured worker identity changed"), cleanupErr)
	}
	pipes, pipeCleanupComplete, err := operations.newPipes()
	if err != nil {
		cleanupErr := errors.Join(image.Close(), container.close())
		return nil,
			cleanupSucceeded(pipeCleanupComplete, cleanupErr),
			errors.Join(err, cleanupErr)
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := errors.Join(pipes.close(), image.Close(), container.close())
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	job, jobCleanupComplete, err := operations.createJob(supervisor.limits)
	if err != nil {
		cleanupErr := errors.Join(pipes.close(), image.Close(), container.close())
		return nil,
			cleanupSucceeded(jobCleanupComplete, cleanupErr),
			errors.Join(err, cleanupErr)
	}
	resources := &launchResources{
		container: container,
		image:     image,
		imagePath: imagePath,
		imageHash: hash,
		pipes:     pipes,
		job:       job,
		cleanup:   supervisor.limits.CleanupTimeout,
	}
	return finishLaunchPreparation(ctx, resources, startupDeadline)
}

func finishLaunchPreparation(
	ctx context.Context,
	resources *launchResources,
	startupDeadline time.Time,
) (*launchResources, bool, error) {
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := resources.close()
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	return resources, true, nil
}

func cleanupSucceeded(previous bool, err error) bool {
	return previous && err == nil
}

func (resources *launchResources) start(
	ctx context.Context,
	startupDeadline time.Time,
) (*launchedProcess, bool, error) {
	return resources.startWith(ctx, startupDeadline, defaultProcessStartOperations())
}

func (resources *launchResources) startWith(
	ctx context.Context,
	startupDeadline time.Time,
	operations processStartOperations,
) (*launchedProcess, bool, error) {
	info, err := operations.start(resources.container, resources.imagePath, resources.pipes)
	if err != nil {
		return nil, true, err
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := resources.stopStart(info, false)
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	if err := operations.assign(resources.job, info.Process); err != nil {
		stopErr := resources.stopStart(info, false)
		return nil, stopErr == nil, errors.Join(
			fmt.Errorf("assign worker job: %w", err),
			stopErr,
		)
	}
	if err := operations.closePipes(&resources.pipes); err != nil {
		stopErr := resources.stopStart(info, true)
		return nil, stopErr == nil, errors.Join(err, stopErr)
	}
	if err := checkStartupContext(ctx, startupDeadline); err != nil {
		cleanupErr := resources.stopStart(info, true)
		return nil, cleanupErr == nil, errors.Join(err, cleanupErr)
	}
	resumedAt := time.Now()
	if _, err := operations.resume(info.Thread); err != nil {
		stopErr := resources.stopStart(info, true)
		return nil, stopErr == nil, errors.Join(
			fmt.Errorf("resume worker: %w", err),
			stopErr,
		)
	}
	return &launchedProcess{
		info:      info,
		job:       resources.job,
		pipes:     resources.pipes,
		container: resources.container,
		image:     resources.image,
		started:   resumedAt,
	}, true, nil
}

func (resources *launchResources) stopStart(
	info windows.ProcessInformation,
	assigned bool,
) error {
	return resources.stopStartWith(info, assigned, defaultStartupStopOperations())
}

func (resources *launchResources) stopStartWith(
	info windows.ProcessInformation,
	assigned bool,
	operations startupStopOperations,
) error {
	pipeErr := operations.closeChild(&resources.pipes)
	var stopErr error
	if assigned {
		stopErr = operations.terminateJob(resources.job, 1)
	} else {
		stopErr = operations.terminateProcess(info.Process, 1)
	}
	complete, waitErr := operations.wait(
		info.Process,
		resources.job,
		resources.cleanup,
	)
	if !complete && waitErr == nil {
		waitErr = errors.New("startup cleanup incomplete")
	}
	return errors.Join(
		pipeErr,
		stopErr,
		waitErr,
		operations.closeHandle(info.Thread),
		operations.closeHandle(info.Process),
	)
}

func (resources *launchResources) close() error {
	closeErr := resources.pipes.close()
	if resources.job != 0 {
		closeErr = errors.Join(closeErr, windows.CloseHandle(resources.job))
	}
	if resources.image != nil {
		closeErr = errors.Join(closeErr, resources.image.Close())
	}
	closeErr = errors.Join(closeErr, resources.container.close())
	return closeErr
}

func createContainerName() (appContainer, error) {
	return createContainerNameWith(rand.Reader, createContainer)
}

func createContainerNameWith(
	randomSource io.Reader,
	create func(string) (appContainer, error),
) (appContainer, error) {
	var random [16]byte
	if _, err := io.ReadFull(randomSource, random[:]); err != nil {
		return appContainer{}, fmt.Errorf("generate AppContainer identity: %w", err)
	}
	return create("celestia.worker." + hex.EncodeToString(random[:]))
}

func newPipes() (pipeSet, bool, error) {
	return newPipesWith(windows.CreatePipe, windows.SetHandleInformation)
}

func newPipesWith(
	create func(*windows.Handle, *windows.Handle, *windows.SecurityAttributes, uint32) error,
	restrict func(windows.Handle, uint32, uint32) error,
) (pipeSet, bool, error) {
	var pipes pipeSet
	security := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	if err := create(&pipes.stdinRead, &pipes.stdinWrite, &security, 0); err != nil {
		return pipes, true, fmt.Errorf("create stdin pipe: %w", err)
	}
	if err := create(&pipes.stdoutRead, &pipes.stdoutWrite, &security, 0); err != nil {
		return failedPipes(pipes, fmt.Errorf("create stdout pipe: %w", err))
	}
	if err := create(&pipes.stderrRead, &pipes.stderrWrite, &security, 0); err != nil {
		return failedPipes(pipes, fmt.Errorf("create stderr pipe: %w", err))
	}
	for _, handle := range []windows.Handle{pipes.stdinWrite, pipes.stdoutRead, pipes.stderrRead} {
		if err := restrict(handle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			return failedPipes(pipes, fmt.Errorf("restrict parent pipe: %w", err))
		}
	}
	return pipes, true, nil
}

func failedPipes(pipes pipeSet, operationErr error) (pipeSet, bool, error) {
	closeErr := pipes.close()
	return pipes, closeErr == nil, errors.Join(operationErr, closeErr)
}

func startSuspended(
	container appContainer,
	imagePath string,
	pipes pipeSet,
) (windows.ProcessInformation, error) {
	return startSuspendedWith(container, imagePath, pipes, defaultSuspendedProcessOperations())
}

func startSuspendedWith(
	container appContainer,
	imagePath string,
	pipes pipeSet,
	operations suspendedProcessOperations,
) (windows.ProcessInformation, error) {
	attributes, err := operations.newAttributes(2)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("create process attributes: %w", err)
	}
	defer attributes.Delete()
	capabilities := securityCapabilities{appContainerSID: container.sid}
	if err := operations.update(
		attributes,
		securityCapabilitiesAttribute,
		nativePointer(&capabilities),
		unsafe.Sizeof(capabilities),
	); err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("set AppContainer: %w", err)
	}
	handles := []windows.Handle{pipes.stdinRead, pipes.stdoutWrite, pipes.stderrWrite}
	if err := operations.update(
		attributes,
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		nativePointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("set inherited handles: %w", err)
	}
	image, err := operations.encode(imagePath)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("encode worker image path: %w", err)
	}
	command, err := operations.encode(windows.EscapeArg(imagePath))
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("encode worker command line: %w", err)
	}
	directory, err := operations.encode(container.folder)
	if err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("encode worker directory: %w", err)
	}
	environment, err := operations.environment(container.folder)
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
	err = operations.create(
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

func failedOutcome(status Status, started time.Time, err error) Outcome {
	return Outcome{
		Status:   status,
		Duration: time.Since(started),
		Err:      err,
	}
}

func (process *launchedProcess) close() error {
	closeErr := process.pipes.close()
	if err := windows.CloseHandle(process.info.Thread); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close worker thread: %w", err))
	}
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
