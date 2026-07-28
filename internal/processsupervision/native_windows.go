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
	ole32                         = windows.NewLazySystemDLL("ole32.dll")
	coTaskMemFree                 = ole32.NewProc("CoTaskMemFree")
	errAppContainerAlreadyExists  = windows.Errno(183)
	errAppContainerNotImplemented = errors.New("AppContainer API unavailable")
)

type securityCapabilities struct {
	appContainerSID *windows.SID
	capabilities    unsafe.Pointer
	capabilityCount uint32
	reserved        uint32
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
	result, _, callErr := createAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namePointer)), // #nosec G103 -- Win32 requires a PCWSTR address.
		uintptr(unsafe.Pointer(display)),     // #nosec G103 -- Win32 requires a PCWSTR address.
		uintptr(unsafe.Pointer(description)), // #nosec G103 -- Win32 requires a PCWSTR address.
		0,
		0,
		uintptr(unsafe.Pointer(&sid)), // #nosec G103 -- Win32 writes the allocated SID pointer.
	)
	if result != 0 {
		if windows.Errno(result&0xffff) == errAppContainerAlreadyExists {
			return appContainer{}, fmt.Errorf("create AppContainer: duplicate profile")
		}
		if errors.Is(callErr, windows.ERROR_PROC_NOT_FOUND) {
			return appContainer{}, errAppContainerNotImplemented
		}
		return appContainer{}, fmt.Errorf("create AppContainer: HRESULT %#x", result)
	}
	if sid == nil {
		container := appContainer{name: name}
		if rollbackErr := container.close(); rollbackErr != nil {
			return container, errors.Join(
				errors.New("create AppContainer: missing SID"),
				fmt.Errorf("rollback AppContainer %s: %w", container.identity(), rollbackErr),
			)
		}
		return appContainer{}, errors.New("create AppContainer: missing SID")
	}
	folder, err := containerFolder(sid)
	if err != nil {
		container := appContainer{name: name, sid: sid}
		if rollbackErr := container.close(); rollbackErr != nil {
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
	result, _, callErr := getAppContainerFolderPath.Call(
		uintptr(unsafe.Pointer(sidText)), // #nosec G103 -- Win32 requires a PCWSTR address.
		uintptr(unsafe.Pointer(&folder)), // #nosec G103 -- Win32 writes the allocated path pointer.
	)
	if result != 0 {
		if errors.Is(callErr, windows.ERROR_PROC_NOT_FOUND) {
			return "", errAppContainerNotImplemented
		}
		return "", fmt.Errorf("get AppContainer folder: HRESULT %#x", result)
	}
	if folder == nil {
		return "", errors.New("get AppContainer folder: missing path")
	}
	defer func() {
		_, _, _ = coTaskMemFree.Call(
			uintptr(unsafe.Pointer(folder)), // #nosec G103 -- Win32 requires the allocated path address.
		)
	}()
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
	result, _, _ := deleteAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namePointer)), // #nosec G103 -- Win32 requires a PCWSTR address.
	)
	if result != 0 {
		return fmt.Errorf("delete AppContainer: HRESULT %#x", result)
	}
	return nil
}

func createJob(limits Limits) (windows.Handle, bool, error) {
	job, err := windows.CreateJobObject(nil, nil)
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
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&information)), // #nosec G103 -- Win32 reads the typed job structure.
		uint32(unsafe.Sizeof(information)),
	)
	if err != nil {
		return failedJob(job, fmt.Errorf("configure job: %w", err))
	}
	return job, true, nil
}

func failedJob(job windows.Handle, operationErr error) (windows.Handle, bool, error) {
	closeErr := windows.CloseHandle(job)
	return 0, closeErr == nil, errors.Join(operationErr, closeErr)
}
