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

package supervision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type launchedProcess struct {
	info      windows.ProcessInformation
	job       windows.Handle
	pipes     pipeSet
	container appContainer
	image     *os.File
	started   time.Time
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
		closeChild:   (*pipeSet).closeChildEnds,
		terminateJob: windows.TerminateJobObject,
		terminateProcess: func(process windows.Handle, _ uint32) error {
			return windows.TerminateProcess(process, 1)
		},
		wait:        waitCleanup,
		closeHandle: windows.CloseHandle,
	}
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
