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

	"crypto/sha256"

	"golang.org/x/sys/windows"
	"os"
	"path/filepath"

	"testing"
	"time"
)

func TestSupervisorRejectsReparseWorker(t *testing.T) {
	link := filepath.Join(t.TempDir(), "worker.exe")
	if err := os.Symlink(os.Args[0], link); err != nil {
		t.Fatalf("create worker symlink: %v", err)
	}
	if _, err := New(link, testNativeLimits()); err == nil {
		t.Fatal("reparse worker was accepted")
	}
}

func TestWorkerPathPolicy(t *testing.T) {
	tests := map[string]struct {
		path string
		want bool
	}{
		"local":            {path: filepath.Join(t.TempDir(), "worker.exe"), want: true},
		"lowercase drive":  {path: `c:\worker.exe`, want: true},
		"before uppercase": {path: `@:\worker.exe`},
		"after uppercase":  {path: `[:\worker.exe`},
		"before lowercase": {path: "`:\\worker.exe"},
		"after lowercase":  {path: `{:\worker.exe`},
		"relative":         {path: "worker.exe"},
		"UNC":              {path: `\\invalid.example\share\worker.exe`},
		"device":           {path: `\\?\C:\worker.exe`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := validWorkerPath(test.path); actual != test.want {
				t.Fatalf("validWorkerPath(%q) = %t, want %t", test.path, actual, test.want)
			}
		})
	}
}

func TestResolvedWorkerPathPolicy(t *testing.T) {
	tests := map[string]struct {
		path      string
		driveType uint32
		want      bool
	}{
		"local":  {path: `\\?\C:\worker.exe`, driveType: windows.DRIVE_FIXED, want: true},
		"mapped": {path: `\\?\Z:\worker.exe`, driveType: windows.DRIVE_REMOTE},
		"UNC":    {path: `\\?\UNC\server\share\worker.exe`, driveType: windows.DRIVE_REMOTE},
		"device": {path: `\Device\Mup\server\share\worker.exe`, driveType: windows.DRIVE_REMOTE},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := validLocalFinalPath(test.path, test.driveType); actual != test.want {
				t.Fatalf("validLocalFinalPath(%q) = %t, want %t", test.path, actual, test.want)
			}
		})
	}
}

func TestSupervisorDetectsWorkerChange(t *testing.T) {
	source := os.Getenv("CELESTIA_TEST_HOSTILE_WORKER")
	worker := filepath.Join(t.TempDir(), "worker.exe")
	copyFile(t, worker, source)
	supervisor, err := New(worker, testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	if err := os.WriteFile(worker, []byte("changed"), 0o600); err != nil {
		t.Fatalf("change worker: %v", err)
	}
	outcome := supervisor.RunBefore(
		context.Background(),
		[]byte("malformed"),
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
	if outcome.Status != StartFailed || outcome.Err == nil {
		t.Fatalf("changed worker: status=%s error=%v", outcome.Status, outcome.Err)
	}
}

func TestSupervisorReportsWorkerHashOnLaunchFailure(t *testing.T) {
	content := []byte("not a Windows executable")
	worker := filepath.Join(t.TempDir(), "worker.exe")
	if err := os.WriteFile(worker, content, 0o600); err != nil {
		t.Fatalf("write worker: %v", err)
	}
	supervisor, err := New(worker, testNativeLimits())
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	outcome := supervisor.RunBefore(
		context.Background(),
		[]byte("malformed"),
		time.Now().Add(supervisor.limits.StartupTimeout),
	)
	expected := sha256.Sum256(content)
	if outcome.Status != StartFailed ||
		outcome.WorkerSHA256 != expected ||
		outcome.Err == nil {
		t.Fatalf(
			"status=%s hash=%x error=%v",
			outcome.Status,
			outcome.WorkerSHA256,
			outcome.Err,
		)
	}
}

func TestStageImageRejectsFailures(t *testing.T) {
	container, err := createContainerName()
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer closeContainer(t, &container)
	if _, _, _, _, err := stageImage(
		container.folder,
		filepath.Join(t.TempDir(), "missing"),
	); err == nil {
		t.Fatal("missing worker was staged")
	}
	image, _, _, complete, err := stageImage(
		container.folder,
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
	)
	if err != nil {
		t.Fatalf("stage worker: %v", err)
	}
	if !complete {
		t.Fatal("successful staging reported incomplete cleanup")
	}
	defer closeFile(t, image)
	if _, _, _, _, err := stageImage(
		container.folder,
		os.Getenv("CELESTIA_TEST_HOSTILE_WORKER"),
	); err == nil {
		t.Fatal("staging collision was accepted")
	}
}

func TestStartRejectsInvalidImage(t *testing.T) {
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
	if _, err := startSuspended(container, filepath.Join(container.folder, "missing.exe"), pipes); err == nil {
		t.Fatal("missing image was started")
	}
}
