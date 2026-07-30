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
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	securityCapabilitiesAttribute = 0x00020009
	startfUseStdHandles           = 0x00000100
	extendedStartupInfoPresent    = 0x00080000
	createSuspended               = 0x00000004
	createNoWindow                = 0x08000000
	createUnicodeEnvironment      = 0x00000400
)

var (
	userenv                       = windows.NewLazySystemDLL("userenv.dll")
	createAppContainerProfile     = userenv.NewProc("CreateAppContainerProfile")
	deleteAppContainerProfile     = userenv.NewProc("DeleteAppContainerProfile")
	getAppContainerFolderPath     = userenv.NewProc("GetAppContainerFolderPath")
	errAppContainerAlreadyExists  = windows.Errno(183)
	errAppContainerNotImplemented = errors.New("AppContainer API unavailable")
)

type securityCapabilities struct {
	appContainerSID *windows.SID
	_               unsafe.Pointer
	_               uint32
	_               uint32
}

type nativeCallResult struct {
	code uintptr
	err  error
}

type appContainer struct {
	name           string
	sid            *windows.SID
	folder         string
	sidReleased    bool
	profileDeleted bool
}

func createContainer(name string) (appContainer, error) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return appContainer{}, fmt.Errorf("encode AppContainer name: %w", err)
	}
	display, err := windows.UTF16PtrFromString("Celestia worker")
	if err != nil {
		return appContainer{}, fmt.Errorf("encode AppContainer display name: %w", err)
	}
	description, err := windows.UTF16PtrFromString("Ephemeral deterministic worker")
	if err != nil {
		return appContainer{}, fmt.Errorf("encode AppContainer description: %w", err)
	}
	var sid *windows.SID
	code, _, callErr := createAppContainerProfile.Call(
		uintptr(nativePointer(namePointer)),
		uintptr(nativePointer(display)),
		uintptr(nativePointer(description)),
		0,
		0,
		uintptr(nativePointer(&sid)),
	)
	return completeContainerCreation(
		name,
		sid,
		nativeCallResult{code: code, err: callErr},
		containerFolder,
		(*appContainer).close,
	)
}

func completeContainerCreation(
	name string,
	sid *windows.SID,
	result nativeCallResult,
	folderFor func(*windows.SID) (string, error),
	rollback func(*appContainer) error,
) (appContainer, error) {
	if result.code != 0 {
		if windows.Errno(result.code&0xffff) == errAppContainerAlreadyExists {
			return appContainer{}, fmt.Errorf("create AppContainer: duplicate profile")
		}
		if errors.Is(result.err, windows.ERROR_PROC_NOT_FOUND) {
			return appContainer{}, errAppContainerNotImplemented
		}
		return appContainer{}, fmt.Errorf("create AppContainer: HRESULT %#x", result.code)
	}
	if sid == nil {
		container := appContainer{name: name}
		if rollbackErr := rollback(&container); rollbackErr != nil {
			return container, errors.Join(
				errors.New("create AppContainer: missing SID"),
				fmt.Errorf("rollback AppContainer %s: %w", container.identity(), rollbackErr),
			)
		}
		return appContainer{}, errors.New("create AppContainer: missing SID")
	}
	folder, err := folderFor(sid)
	if err != nil {
		container := appContainer{name: name, sid: sid}
		if rollbackErr := rollback(&container); rollbackErr != nil {
			return container, errors.Join(
				err,
				fmt.Errorf("rollback AppContainer %s: %w", container.identity(), rollbackErr),
			)
		}
		return appContainer{}, err
	}
	return appContainer{name: name, sid: sid, folder: folder}, nil
}

func containerFolder(sid *windows.SID) (string, error) {
	if sid == nil {
		return "", errors.New("get AppContainer folder: missing SID")
	}
	sidText, err := windows.UTF16PtrFromString(sid.String())
	if err != nil {
		return "", fmt.Errorf("encode AppContainer SID: %w", err)
	}
	var folder *uint16
	code, _, callErr := getAppContainerFolderPath.Call(
		uintptr(nativePointer(sidText)),
		uintptr(nativePointer(&folder)),
	)
	return completeContainerFolder(
		folder,
		nativeCallResult{code: code, err: callErr},
		func() {
			windows.CoTaskMemFree(
				nativePointer(folder),
			)
		},
	)
}

func completeContainerFolder(
	folder *uint16,
	result nativeCallResult,
	free func(),
) (string, error) {
	if result.code != 0 {
		if errors.Is(result.err, windows.ERROR_PROC_NOT_FOUND) {
			return "", errAppContainerNotImplemented
		}
		return "", fmt.Errorf("get AppContainer folder: HRESULT %#x", result.code)
	}
	if folder == nil {
		return "", errors.New("get AppContainer folder: missing path")
	}
	defer free()
	return windows.UTF16PtrToString(folder), nil
}

func (container *appContainer) close() error {
	return container.closeWith(windows.FreeSid, deleteContainer)
}

func (container *appContainer) closeWith(
	freeSID func(*windows.SID) error,
	deleteProfile func(string) error,
) error {
	var closeErr error
	identity := container.identity()
	if !container.sidReleased {
		if container.sid == nil {
			container.sidReleased = true
		} else {
			if err := freeSID(container.sid); err != nil {
				closeErr = errors.Join(
					closeErr,
					fmt.Errorf("free AppContainer SID %s: %w", identity, err),
				)
			} else {
				container.sid = nil
				container.sidReleased = true
			}
		}
	}
	if !container.profileDeleted {
		if err := deleteProfile(container.name); err != nil {
			closeErr = errors.Join(
				closeErr,
				fmt.Errorf("delete AppContainer profile %s: %w", identity, err),
			)
		} else {
			container.profileDeleted = true
		}
	}
	return closeErr
}

func (container *appContainer) identity() string {
	sid := "<nil>"
	if container.sid != nil {
		sid = container.sid.String()
	}
	return fmt.Sprintf("name=%q sid=%s", container.name, sid)
}

func deleteContainer(name string) error {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encode AppContainer name: %w", err)
	}
	result, _, callErr := deleteAppContainerProfile.Call(
		uintptr(nativePointer(namePointer)),
	)
	return completeContainerDeletion(result, callErr)
}

func completeContainerDeletion(result uintptr, callErr error) error {
	if result != 0 {
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return fmt.Errorf(
				"delete AppContainer: HRESULT %#x: %w",
				result,
				callErr,
			)
		}
		return fmt.Errorf("delete AppContainer: HRESULT %#x", result)
	}
	return nil
}

func createJob(limits Limits) (windows.Handle, bool, error) {
	return createJobWith(
		limits,
		func() (windows.Handle, error) {
			return windows.CreateJobObject(nil, nil)
		},
		func(job windows.Handle, information windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
			_, err := windows.SetInformationJobObject(
				job,
				windows.JobObjectExtendedLimitInformation,
				uintptr(nativePointer(&information)),
				uint32(unsafe.Sizeof(information)),
			)
			return err
		},
		windows.CloseHandle,
	)
}

func createJobWith(
	limits Limits,
	create func() (windows.Handle, error),
	configure func(windows.Handle, windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error,
	closeJob func(windows.Handle) error,
) (windows.Handle, bool, error) {
	job, err := create()
	if err != nil {
		return 0, true, fmt.Errorf("create job: %w", err)
	}
	information := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	information.BasicLimitInformation.PerProcessUserTimeLimit = limits.Timeout.Nanoseconds() / 100
	information.BasicLimitInformation.ActiveProcessLimit = limits.Processes
	information.BasicLimitInformation.LimitFlags =
		windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
			windows.JOB_OBJECT_LIMIT_PROCESS_TIME |
			windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
			windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	information.JobMemoryLimit = uintptr(limits.MemoryBytes)
	if err := configure(job, information); err != nil {
		return failedJobWith(job, fmt.Errorf("configure job: %w", err), closeJob)
	}
	return job, true, nil
}

func failedJob(job windows.Handle, operationErr error) (windows.Handle, bool, error) {
	return failedJobWith(job, operationErr, windows.CloseHandle)
}

func failedJobWith(
	job windows.Handle,
	operationErr error,
	closeJob func(windows.Handle) error,
) (windows.Handle, bool, error) {
	closeErr := closeJob(job)
	return 0, closeErr == nil, errors.Join(operationErr, closeErr)
}
