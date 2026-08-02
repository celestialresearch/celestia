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
	"os"

	"testing"
	"time"
)

func TestFailedLaunchPreservesCleanupState(t *testing.T) {
	outcome := failedLaunchOutcome(time.Now(), false, errors.New("cleanup"))
	if outcome.Status != StartFailed || outcome.CleanupComplete {
		t.Fatalf(
			"status=%s cleanup=%t",
			outcome.Status,
			outcome.CleanupComplete,
		)
	}
}

func TestRunRejectsExpiredStartupDeadline(t *testing.T) {
	supervisor, err := New(os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"), testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	outcome := supervisor.RunBefore(context.Background(), []byte("{}"), time.Now().Add(-time.Second))
	if outcome.Status != StartFailed ||
		!outcome.CleanupComplete ||
		!errors.Is(outcome.Err, context.DeadlineExceeded) {
		t.Fatalf("status=%s cleanup=%t error=%v", outcome.Status, outcome.CleanupComplete, outcome.Err)
	}
}

func TestPrepareLaunchCleansCancelledStartup(t *testing.T) {
	supervisor, err := New(os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"), testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resources, complete, err := supervisor.prepareLaunch(
		ctx,
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
	if resources != nil ||
		!complete ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("resources=%v complete=%t error=%v", resources, complete, err)
	}
}

func TestCleanupSucceeded(t *testing.T) {
	if !cleanupSucceeded(true, nil) {
		t.Fatal("successful cleanup rejected")
	}
	if cleanupSucceeded(false, nil) || cleanupSucceeded(true, errors.New("cleanup")) {
		t.Fatal("incomplete cleanup accepted")
	}
}

func TestStartupCleanupJoinsWorker(t *testing.T) {
	for _, assigned := range []bool{false, true} {
		t.Run(map[bool]string{false: "unassigned", true: "assigned"}[assigned], func(t *testing.T) {
			supervisor, err := New(
				os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
				testNativeLimits(),
			)
			if err != nil {
				t.Fatalf("new supervisor: %v", err)
			}
			resources, _, err := supervisor.prepareLaunch(
				context.Background(),
				time.Now().Add(testNativeLimits().StartupTimeout),
			)
			if err != nil {
				t.Fatalf("prepare launch: %v", err)
			}
			defer func() {
				if err := resources.close(); err != nil {
					t.Errorf("close resources: %v", err)
				}
			}()
			info, err := startSuspended(
				resources.container,
				resources.imagePath,
				resources.pipes,
			)
			if err != nil {
				t.Fatalf("start suspended: %v", err)
			}
			if assigned {
				if err := windows.AssignProcessToJobObject(
					resources.job,
					info.Process,
				); err != nil {
					t.Fatalf("assign process: %v", err)
				}
			}
			if err := resources.stopStart(info, assigned); err != nil {
				t.Fatalf("stop startup: %v", err)
			}
		})
	}
}

func TestCancelledStartupNeverResumesWorker(t *testing.T) {
	supervisor, err := New(
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
		testNativeLimits(),
	)
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	resources, _, err := supervisor.prepareLaunch(
		context.Background(),
		time.Now().Add(testNativeLimits().StartupTimeout),
	)
	if err != nil {
		t.Fatalf("prepare launch: %v", err)
	}
	defer func() {
		if err := resources.close(); err != nil {
			t.Errorf("close resources: %v", err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	process, complete, err := resources.start(
		ctx,
		time.Now().Add(testNativeLimits().StartupTimeout),
	)
	if process != nil || !complete || !errors.Is(err, context.Canceled) {
		t.Fatalf("process=%v complete=%t error=%v", process, complete, err)
	}
	outcome := failedLaunchOutcome(time.Now(), complete, err)
	if outcome.Status != Cancelled || !outcome.CleanupComplete {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestExpiredLaunchPreparationClosesPipes(t *testing.T) {
	pipes, complete, err := newPipes()
	if err != nil || !complete {
		t.Fatalf("create pipes: complete=%t error=%v", complete, err)
	}
	resources := &launchResources{
		container: appContainer{
			sidReleased:    true,
			profileDeleted: true,
		},
		pipes: pipes,
	}
	prepared, complete, err := finishLaunchPreparation(
		context.Background(),
		resources,
		time.Now().Add(-time.Second),
	)
	if prepared != nil || !complete || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("prepared=%v complete=%t error=%v", prepared, complete, err)
	}
	if resources.pipes != (pipeSet{}) {
		t.Fatalf("pipe handles retained: %#v", resources.pipes)
	}
}
