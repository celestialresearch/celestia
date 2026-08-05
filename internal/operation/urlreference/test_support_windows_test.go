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

package urloperation

import (
	"celestia.research/celestia/internal/operation/urlreference/admission"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"celestia.research/celestia/internal/testcargo"
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestMain(testingMain *testing.M) {
	root, err := repositoryRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := testcargo.Build(ctx, testcargo.Request{
		Arguments: []string{"build", "--workspace", "--all-targets", "--locked", "--target", "x86_64-pc-windows-msvc"},
		Directory: root,
		Environment: cargoTargetEnvironment(
			os.Environ(), filepath.Join(root, "target", "celestia-tests"),
		),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "build production worker: %v\n", err)
		os.Exit(1)
	}
	if err := testcargo.Build(ctx, testcargo.Request{
		Arguments: []string{
			"build", "--manifest-path", "worker/qualification-fixtures/Cargo.toml", "--bins", "--locked",
			"--target", "x86_64-pc-windows-msvc",
		},
		Directory: root,
		Environment: cargoTargetEnvironment(
			os.Environ(), filepath.Join(root, "target", "celestia-qualification-tests"),
		),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "build qualification fixtures: %v\n", err)
		os.Exit(1)
	}
	cancel()
	os.Exit(testingMain.Run())
}

func admittedFixture(t *testing.T, admittedAt time.Time) urladmission.Accepted {
	t.Helper()
	accepted, err := urladmission.Admit(
		"https://example.test",
		urlreference.Defang,
		admittedAt,
	)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	return accepted
}

func newTestOperation(t *testing.T, worker string) (*Operation, error) {
	t.Helper()
	return New(worker, testEvidenceRoot(t))
}

func testEvidenceRoot(tb testing.TB) string {
	tb.Helper()
	return testEvidenceRootAt(tb, tb.TempDir())
}

func testEvidenceRootAt(tb testing.TB, directory string) string {
	tb.Helper()
	parent := filepath.Join(directory, "owned")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		tb.Fatalf("current user: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)", user.User.Sid, user.User.Sid),
	)
	if err != nil {
		tb.Fatalf("evidence parent descriptor: %v", err)
	}
	pointer, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		tb.Fatalf("evidence parent path: %v", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pointer, &attributes); err != nil {
		tb.Fatalf("create evidence parent: %v", err)
	}
	return filepath.Join(parent, "evidence")
}

func testWorker(t *testing.T) string {
	t.Helper()
	return locateWorker(t, "celestia-url-reference.exe")
}

func testHostileWorker(t *testing.T) string {
	t.Helper()
	return locateWorker(t, "celestia-hostile-worker.exe")
}

func locateWorker(tb testing.TB, name string) string {
	tb.Helper()
	root, err := repositoryRoot()
	if err != nil {
		tb.Fatalf("repository root: %v", err)
	}
	binaryDirectory := filepath.Join(
		root, "target", "celestia-tests", "x86_64-pc-windows-msvc", "debug",
	)
	if name == "celestia-hostile-worker.exe" || name == "celestia-blocked-input-worker.exe" {
		binaryDirectory = filepath.Join(
			root, "target", "celestia-qualification-tests", "x86_64-pc-windows-msvc", "debug",
		)
	}
	path := filepath.Join(binaryDirectory, name)
	if _, err := os.Stat(path); err != nil {
		tb.Fatalf("worker %s is unavailable: %v", name, err)
	}
	return path
}

func cargoTargetEnvironment(environment []string, target string) []string {
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(strings.ToUpper(entry), "CARGO_TARGET_DIR=") {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, "CARGO_TARGET_DIR="+target)
}

func TestCargoTargetEnvironmentReplacesAmbientTarget(t *testing.T) {
	environment := cargoTargetEnvironment(
		[]string{"PATH=fixture", "CARGO_TARGET_DIR=stale", "cargo_target_dir=other"},
		"owned",
	)
	if got := strings.Join(environment, "|"); got != "PATH=fixture|CARGO_TARGET_DIR=owned" {
		t.Fatalf("environment=%q", got)
	}
}

func repositoryRoot() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("working directory: %w", err)
	}
	return filepath.Clean(filepath.Join(workingDirectory, "..", "..", "..")), nil
}
