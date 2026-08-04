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
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateContainerNameReportsRandomFailure(t *testing.T) {
	t.Parallel()
	called := false
	_, err := createContainerNameWith(
		strings.NewReader("short"),
		func(string) (appContainer, error) {
			called = true
			return appContainer{}, nil
		},
	)
	if err == nil || called {
		t.Fatalf("error=%v create-called=%t", err, called)
	}
}

func TestCreateContainerNamePassesRandomIdentity(t *testing.T) {
	t.Parallel()
	var name string
	_, err := createContainerNameWith(
		bytes.NewReader(make([]byte, 16)),
		func(value string) (appContainer, error) {
			name = value
			return appContainer{}, nil
		},
	)
	if err != nil {
		t.Fatalf("create container name: %v", err)
	}
	if name != "celestia.worker.00000000000000000000000000000000" {
		t.Fatalf("container name = %q", name)
	}
}

func TestNewSupervisorReportsMeasurementFailures(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "worker.exe")
	if err := os.WriteFile(path, []byte("worker"), 0o600); err != nil {
		t.Fatalf("write worker: %v", err)
	}
	failure := errors.New("injected measurement failure")

	for _, failHash := range []bool{false, true} {
		worker, err := openLocalImage(path)
		if err != nil {
			t.Fatalf("open worker: %v", err)
		}
		_, err = newSupervisorWith(path, testNativeLimits(), supervisorCreationOperations{
			open: func(string) (*os.File, error) { return worker, nil },
			hash: func(*os.File) ([32]byte, error) {
				if failHash {
					return [32]byte{}, failure
				}
				return [32]byte{}, nil
			},
			close: func(file *os.File) error {
				closeErr := file.Close()
				if failHash {
					return closeErr
				}
				return errors.Join(closeErr, failure)
			},
		})
		if !errors.Is(err, errInvalid) || !errors.Is(err, failure) {
			t.Fatalf("hash-failure=%t error=%v", failHash, err)
		}
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

type preparationFailureCase struct {
	name       string
	replace    func(*launchPreparationOperations)
	incomplete bool
}

func launchAcquisitionFailures(failure error) []preparationFailureCase {
	return []preparationFailureCase{
		{
			name: "container",
			replace: func(operations *launchPreparationOperations) {
				operations.createContainer = func() (appContainer, error) {
					return appContainer{}, failure
				}
			},
		},
		{
			name: "partial container",
			replace: func(operations *launchPreparationOperations) {
				operations.createContainer = func() (appContainer, error) {
					return appContainer{
						name:           "partial",
						sidReleased:    true,
						profileDeleted: true,
					}, failure
				}
			},
		},
		{
			name: "image",
			replace: func(operations *launchPreparationOperations) {
				operations.stageImage = func(
					string,
					string,
				) (*os.File, [32]byte, string, bool, error) {
					return nil, [32]byte{}, "", true, failure
				}
			},
		},
		{
			name: "pipes",
			replace: func(operations *launchPreparationOperations) {
				operations.newPipes = func() (pipeSet, bool, error) {
					return pipeSet{}, true, failure
				}
			},
		},
		{
			name: "job",
			replace: func(operations *launchPreparationOperations) {
				operations.createJob = func(Limits) (windows.Handle, bool, error) {
					return 0, true, failure
				}
			},
		},
	}
}

func launchCleanupFailures(failure error) []preparationFailureCase {
	return []preparationFailureCase{
		{
			name: "image cleanup",
			replace: func(operations *launchPreparationOperations) {
				operations.stageImage = func(
					string,
					string,
				) (*os.File, [32]byte, string, bool, error) {
					return nil, [32]byte{}, "", false, failure
				}
			},
			incomplete: true,
		},
		{
			name: "pipe cleanup",
			replace: func(operations *launchPreparationOperations) {
				operations.newPipes = func() (pipeSet, bool, error) {
					return pipeSet{}, false, failure
				}
			},
			incomplete: true,
		},
		{
			name: "job cleanup",
			replace: func(operations *launchPreparationOperations) {
				operations.createJob = func(Limits) (windows.Handle, bool, error) {
					return 0, false, failure
				}
			},
			incomplete: true,
		},
	}
}

func TestPrepareLaunchReportsOperationFailures(t *testing.T) {
	t.Parallel()

	supervisor := testSupervisor(t)
	failure := errors.New("injected launch preparation failure")
	tests := append(
		launchAcquisitionFailures(failure),
		launchCleanupFailures(failure)...,
	)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			operations := defaultLaunchPreparationOperations()
			test.replace(&operations)
			resources, complete, err := supervisor.prepareLaunchWith(
				context.Background(),
				time.Now().Add(testNativeLimits().StartupTimeout),
				operations,
			)
			if resources != nil || err == nil || !strings.Contains(err.Error(), failure.Error()) {
				t.Fatalf("resources=%v complete=%t error=%v", resources, complete, err)
			}
			if complete == test.incomplete {
				t.Fatalf("cleanup complete=%t, want %t", complete, !test.incomplete)
			}
		})
	}
}

func TestPrepareLaunchHonoursContextAtBoundaries(t *testing.T) {
	t.Parallel()

	supervisor := testSupervisor(t)
	tests := []struct {
		name    string
		replace func(*launchPreparationOperations, context.CancelFunc)
	}{
		{
			name: "container",
			replace: func(
				operations *launchPreparationOperations,
				cancel context.CancelFunc,
			) {
				create := operations.createContainer
				operations.createContainer = func() (appContainer, error) {
					container, err := create()
					cancel()
					return container, err
				}
			},
		},
		{
			name: "image",
			replace: func(
				operations *launchPreparationOperations,
				cancel context.CancelFunc,
			) {
				stage := operations.stageImage
				operations.stageImage = func(
					folder string,
					source string,
				) (*os.File, [32]byte, string, bool, error) {
					image, hash, path, complete, err := stage(folder, source)
					cancel()
					return image, hash, path, complete, err
				}
			},
		},
		{
			name: "pipes",
			replace: func(
				operations *launchPreparationOperations,
				cancel context.CancelFunc,
			) {
				create := operations.newPipes
				operations.newPipes = func() (pipeSet, bool, error) {
					pipes, complete, err := create()
					cancel()
					return pipes, complete, err
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			operations := defaultLaunchPreparationOperations()
			test.replace(&operations, cancel)
			resources, complete, err := supervisor.prepareLaunchWith(
				ctx,
				time.Now().Add(testNativeLimits().StartupTimeout),
				operations,
			)
			if resources != nil || !complete || !errors.Is(err, context.Canceled) {
				t.Fatalf("resources=%v complete=%t error=%v", resources, complete, err)
			}
		})
	}
}

func testSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	supervisor, err := New(os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"), testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	return supervisor
}

func preparedLaunch(t *testing.T) *launchResources {
	t.Helper()
	supervisor := testSupervisor(t)
	resources, complete, err := supervisor.prepareLaunch(
		context.Background(),
		time.Now().Add(testNativeLimits().StartupTimeout),
	)
	if err != nil || !complete {
		t.Fatalf("prepare launch: complete=%t error=%v", complete, err)
	}
	return resources
}

func closeLaunchResources(t *testing.T, resources *launchResources) {
	t.Helper()
	if err := resources.close(); err != nil {
		t.Errorf("close launch resources: %v", err)
	}
}
