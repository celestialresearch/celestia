#!/usr/bin/env bash
# Copyright © 2026 @sudocelestia. All rights reserved.
#
# PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
#
# No licence, permission or authorisation is granted to use, copy, modify,
# compile, execute, distribute, publish, sublicense or otherwise exploit this
# file, except to the limited extent unavoidably permitted by applicable law
# or GitHub's Terms of Service.
#
# See the LICENSE file at the repository root for the complete terms.


set -euo pipefail
export GOWORK=off

main() (
work_dir=$2
output=
status=0
printf '%s\n' '// probe' >"$work_dir/coverage_test.go"
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh source-files 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted coverage_test.go\n' >&2
  return 1
}
grep -Fq 'use an intent-named residual coverage file' <<<"$output" || {
  printf 'policy output omitted the rejected filename:\n%s\n' \
    "$output" >&2
  return 1
}
rm -- "$work_dir/coverage_test.go"

cat >"$work_dir/helper.go" <<'EOF'
package fixture

import "testing"

func testContext(t *testing.T) *testing.T {
	return t
}

type skipper interface {
	Skip(...any)
}

func hideSkip(value skipper) {
	value.Skip("unverified")
}
EOF
cat >"$work_dir/aliased_exit.go" <<'EOF'
package fixture

import "os"

var processExit = os.Exit
EOF
cat >"$work_dir/skipped_test.go" <<'EOF'
package fixture

import (
	"os"
	"testing"
)

func TestMain(testingMain *testing.M) {
	if true {
		return
	}
	os.Exit(testingMain.Run())
}

func TestDirectSkip(t *testing.T) {
	t.Skip("unverified")
}

func TestCrossFileSkip(t *testing.T) {
	testContext(t).Skip("unverified")
	hideSkip(t)
}

func TestMethodExpressionSkip(t *testing.T) {
	(*testing.T).Skip(t, "unverified")
}
EOF
cat >"$work_dir/platform_linux.go" <<'EOF'
//go:build linux

package fixture

const platform = "linux"
EOF
cat >"$work_dir/platform_windows.go" <<'EOF'
//go:build windows

package fixture

const platform = "windows"
EOF
cat >"$work_dir/raw_exit_linux.go" <<'EOF'
//go:build linux

package fixture

import "syscall"

func init() {
	syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
}
EOF
cat >"$work_dir/all_threads_exit_linux.go" <<'EOF'
//go:build linux

package fixture

import "syscall"

func init() {
	syscall.AllThreadsSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
}
EOF
cat >"$work_dir/exit_windows.go" <<'EOF'
//go:build windows

package fixture

import "syscall"

func init() {
	syscall.ExitProcess(0)
}
EOF
cat >"$work_dir/exit_wasip1.go" <<'EOF'
//go:build wasip1

package fixture

import "syscall"

func init() {
	syscall.ProcExit(0)
}
EOF
cat >"$work_dir/terminate_self_windows.go" <<'EOF'
//go:build windows

package fixture

import "golang.org/x/sys/windows"

func init() {
	windows.TerminateProcess(windows.CurrentProcess(), 0)
}
EOF
cat >"$work_dir/dynamic_exit_windows.go" <<'EOF'
//go:build windows

package fixture

import "golang.org/x/sys/windows"

func init() {
	windows.NewLazySystemDLL("kernel32.dll").NewProc("ExitProcess").Call(0)
}
EOF
cat >"$work_dir/dynamic_terminate_windows.go" <<'EOF'
//go:build windows

package fixture

import "golang.org/x/sys/windows"

func init() {
	windows.NewLazySystemDLL("kernel32.dll").
		NewProc("TerminateProcess").
		Call(uintptr(windows.CurrentProcess()), 0)
}
EOF
cat >"$work_dir/aliased_resolver_windows.go" <<'EOF'
//go:build windows

package fixture

import "golang.org/x/sys/windows"

func init() {
	resolve := windows.NewLazySystemDLL("kernel32.dll").NewProc
	resolve("ExitProcess").Call(0)
}
EOF
cat >"$work_dir/method_resolver_windows.go" <<'EOF'
//go:build windows

package fixture

import "golang.org/x/sys/windows"

func init() {
	dll := windows.NewLazySystemDLL("kernel32.dll")
	(*windows.LazyDLL).NewProc(dll, "ExitProcess").Call(0)
}
EOF
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh test-skips 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted Go skip variants\n' >&2
  return 1
}
grep -Fq 'Go tests must not skip cases' <<<"$output" || {
  printf 'policy output omitted the skipped-test failure:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Fq 'TestMain violates the local execution syntax' <<<"$output" || {
  printf 'policy output omitted the TestMain failure:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Fq 'Go tests must not use raw system calls' <<<"$output" || {
  printf 'policy output omitted the raw-system-call failure:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Fq 'Go tests must not alias process exit' <<<"$output" || {
  printf 'policy output omitted the process-exit failure:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Fq 'Go tests must not terminate the test process' <<<"$output" || {
  printf 'policy output omitted the self-termination failure:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Fq 'Go tests must not resolve process exit dynamically' \
  <<<"$output" || {
  printf 'policy output omitted the dynamic-exit failure:\n%s\n' \
    "$output" >&2
  return 1
}
for expected_file in \
  aliased_exit.go \
  raw_exit_linux.go \
  all_threads_exit_linux.go \
  exit_windows.go \
  exit_wasip1.go \
  terminate_self_windows.go \
  dynamic_exit_windows.go \
  dynamic_terminate_windows.go \
  aliased_resolver_windows.go \
  method_resolver_windows.go
do
  grep -Fq "$expected_file:" <<<"$output" || {
    printf 'policy output omitted %s:\n%s\n' \
      "$expected_file" "$output" >&2
    return 1
  }
done
rm -- \
  "$work_dir/aliased_exit.go" \
  "$work_dir/helper.go" \
  "$work_dir/skipped_test.go" \
  "$work_dir/platform_linux.go" \
  "$work_dir/platform_windows.go" \
  "$work_dir/raw_exit_linux.go" \
  "$work_dir/all_threads_exit_linux.go" \
  "$work_dir/exit_windows.go" \
  "$work_dir/exit_wasip1.go" \
  "$work_dir/terminate_self_windows.go" \
  "$work_dir/dynamic_exit_windows.go" \
  "$work_dir/dynamic_terminate_windows.go" \
  "$work_dir/aliased_resolver_windows.go" \
  "$work_dir/method_resolver_windows.go"

)

main "$@"
