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
	"golang.org/x/sys/windows"

	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestStopStartReportsIncompleteCleanup(t *testing.T) {
	t.Parallel()
	resources := launchResources{job: 11, cleanup: time.Second}
	info := windows.ProcessInformation{Process: 12, Thread: 13}

	for _, assigned := range []bool{false, true} {
		jobCalls := 0
		processCalls := 0
		closeCalls := 0
		err := resources.stopStartWith(info, assigned, startupStopOperations{
			closeChild: func(*pipeSet) error { return nil },
			terminateJob: func(windows.Handle, uint32) error {
				jobCalls++
				return nil
			},
			terminateProcess: func(windows.Handle, uint32) error {
				processCalls++
				return nil
			},
			wait: func(
				windows.Handle,
				windows.Handle,
				time.Duration,
			) (bool, error) {
				return false, nil
			},
			closeHandle: func(windows.Handle) error {
				closeCalls++
				return nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "startup cleanup incomplete") {
			t.Fatalf("assigned=%t error=%v", assigned, err)
		}
		if jobCalls != boolCount(assigned) ||
			processCalls != boolCount(!assigned) || closeCalls != 2 {
			t.Fatalf(
				"assigned=%t job=%d process=%d close=%d",
				assigned, jobCalls, processCalls, closeCalls,
			)
		}
	}
}

type suspendedFailureCase struct {
	name    string
	want    string
	replace func(*suspendedProcessOperations)
}

func TestStartReportsOperationFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected process start failure")
	tests := []struct {
		name    string
		replace func(*processStartOperations)
	}{
		{
			name: "create suspended process",
			replace: func(operations *processStartOperations) {
				operations.start = func(
					appContainer,
					string,
					pipeSet,
				) (windows.ProcessInformation, error) {
					return windows.ProcessInformation{}, failure
				}
			},
		},
		{
			name: "assign job",
			replace: func(operations *processStartOperations) {
				operations.assign = func(windows.Handle, windows.Handle) error {
					return failure
				}
			},
		},
		{
			name: "close child pipes",
			replace: func(operations *processStartOperations) {
				operations.closePipes = func(*pipeSet) error {
					return failure
				}
			},
		},
		{
			name: "resume thread",
			replace: func(operations *processStartOperations) {
				operations.resume = func(windows.Handle) (uint32, error) {
					return 0, failure
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resources := preparedLaunch(t)
			defer closeLaunchResources(t, resources)
			operations := defaultProcessStartOperations()
			test.replace(&operations)
			process, complete, err := resources.startWith(
				context.Background(),
				time.Now().Add(testNativeLimits().StartupTimeout),
				operations,
			)
			if process != nil || !complete || err == nil ||
				!strings.Contains(err.Error(), failure.Error()) {
				t.Fatalf("process=%v complete=%t error=%v", process, complete, err)
			}
		})
	}
}

func TestStartHonoursContextAfterAssignment(t *testing.T) {
	t.Parallel()

	resources := preparedLaunch(t)
	defer closeLaunchResources(t, resources)
	ctx, cancel := context.WithCancel(context.Background())
	operations := defaultProcessStartOperations()
	assign := operations.assign
	operations.assign = func(job windows.Handle, process windows.Handle) error {
		err := assign(job, process)
		cancel()
		return err
	}
	process, complete, err := resources.startWith(
		ctx,
		time.Now().Add(testNativeLimits().StartupTimeout),
		operations,
	)
	if process != nil || !complete || !errors.Is(err, context.Canceled) {
		t.Fatalf("process=%v complete=%t error=%v", process, complete, err)
	}
}

func TestStartSuspendedReportsOperationFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("injected suspended process failure")
	tests := append(
		suspendedAttributeFailures(failure),
		suspendedEncodingFailures(failure)...,
	)
	tests = append(tests, suspendedRuntimeFailures(failure)...)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertSuspendedFailure(t, test)
		})
	}
}

func suspendedAttributeFailures(failure error) []suspendedFailureCase {
	return []suspendedFailureCase{
		{
			name: "attributes",
			want: "create process attributes",
			replace: func(operations *suspendedProcessOperations) {
				operations.newAttributes = func(
					uint32,
				) (*windows.ProcThreadAttributeListContainer, error) {
					return nil, failure
				}
			},
		},
		{
			name: "AppContainer attribute",
			want: "set AppContainer",
			replace: func(operations *suspendedProcessOperations) {
				operations.update = func(
					*windows.ProcThreadAttributeListContainer,
					uintptr,
					unsafe.Pointer,
					uintptr,
				) error {
					return failure
				}
			},
		},
		{
			name: "handle attribute",
			want: "set inherited handles",
			replace: func(operations *suspendedProcessOperations) {
				update := operations.update
				calls := 0
				operations.update = func(
					attributes *windows.ProcThreadAttributeListContainer,
					attribute uintptr,
					value unsafe.Pointer,
					size uintptr,
				) error {
					calls++
					if calls == 2 {
						return failure
					}
					return update(attributes, attribute, value, size)
				}
			},
		},
	}
}

func suspendedEncodingFailures(failure error) []suspendedFailureCase {
	return []suspendedFailureCase{
		{
			name: "image",
			want: "encode worker image path",
			replace: func(operations *suspendedProcessOperations) {
				operations.encode = func(string) (*uint16, error) {
					return nil, failure
				}
			},
		},
		{
			name: "command",
			want: "encode worker command line",
			replace: func(operations *suspendedProcessOperations) {
				encode := operations.encode
				calls := 0
				operations.encode = func(value string) (*uint16, error) {
					calls++
					if calls == 2 {
						return nil, failure
					}
					return encode(value)
				}
			},
		},
		{
			name: "directory",
			want: "encode worker directory",
			replace: func(operations *suspendedProcessOperations) {
				encode := operations.encode
				calls := 0
				operations.encode = func(value string) (*uint16, error) {
					calls++
					if calls == 3 {
						return nil, failure
					}
					return encode(value)
				}
			},
		},
	}
}

func suspendedRuntimeFailures(failure error) []suspendedFailureCase {
	return []suspendedFailureCase{
		{
			name: "environment",
			want: failure.Error(),
			replace: func(operations *suspendedProcessOperations) {
				operations.environment = func(string) ([]uint16, error) {
					return nil, failure
				}
			},
		},
		{
			name: "create process",
			want: "start AppContainer worker",
			replace: func(operations *suspendedProcessOperations) {
				operations.create = func(
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
				) error {
					return failure
				}
			},
		},
	}
}

func assertSuspendedFailure(t *testing.T, test suspendedFailureCase) {
	t.Helper()
	container, err := createContainerName()
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer closeContainer(t, &container)
	pipes, complete, err := newPipes()
	if err != nil || !complete {
		t.Fatalf("create pipes: complete=%t error=%v", complete, err)
	}
	defer func() {
		if err := pipes.close(); err != nil {
			t.Errorf("close pipes: %v", err)
		}
	}()
	operations := defaultSuspendedProcessOperations()
	test.replace(&operations)
	info, err := startSuspendedWith(
		container,
		`C:\missing-worker.exe`,
		pipes,
		operations,
	)
	if info.Process != 0 || info.Thread != 0 || err == nil ||
		!strings.Contains(err.Error(), test.want) {
		t.Fatalf("process=%v thread=%v error=%v", info.Process, info.Thread, err)
	}
}
