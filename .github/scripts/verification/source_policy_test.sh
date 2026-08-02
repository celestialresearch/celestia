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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=.github/scripts/verification/fixture.sh
source "$script_dir/fixture.sh"

main() (
root=$(cd -- "$script_dir/../../.." && pwd)
work_dir=$(new_verification_work verification-source-policy)
trap 'cleanup_verification "$work_dir" "$fifo_pid"' EXIT
trap '[[ $- != *e* ]] || printf "verification-source-policy failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

fifo_pid=
mkdir -p \
  "$work_dir/.github/scripts" \
  "$work_dir/a" \
  "$work_dir/b" \
  "$work_dir/docs/contracts" \
  "$work_dir/tools/sourcepolicy"
cp "$root/.github/scripts/coveragecheck.sh" \
  "$root/.github/scripts/modcheck.sh" \
  "$root/.github/scripts/policycheck.sh" \
  "$work_dir/.github/scripts/"
cp \
  "$root/tools/sourcepolicy/gofallback.go" \
  "$root/tools/sourcepolicy/architecture.go" \
  "$root/tools/sourcepolicy/architecture_attempt_split.go" \
  "$root/tools/sourcepolicy/architecture_inventory.go" \
  "$root/tools/sourcepolicy/architecture_limits.go" \
  "$root/tools/sourcepolicy/architecture_imports.go" \
  "$root/tools/sourcepolicy/architecture_paths.go" \
  "$root/tools/sourcepolicy/architecture_rust.go" \
  "$root/tools/sourcepolicy/architecture_scripts.go" \
  "$root/tools/sourcepolicy/architecture_split.go" \
  "$root/tools/sourcepolicy/architecture_values.go" \
  "$root/tools/sourcepolicy/executable_inventory.go" \
  "$root/tools/sourcepolicy/gobuildtags.go" \
  "$root/tools/sourcepolicy/goinspect.go" \
  "$root/tools/sourcepolicy/goskip.go" \
  "$root/tools/sourcepolicy/main.go" \
  "$root/tools/sourcepolicy/manifest.go" \
  "$root/tools/sourcepolicy/module_replacement.go" \
  "$root/tools/sourcepolicy/rustpolicy.go" \
  "$root/tools/sourcepolicy/source_open_other.go" \
  "$root/tools/sourcepolicy/source_open_unix.go" \
  "$root/tools/sourcepolicy/suppression.go" \
  "$root/tools/sourcepolicy/testinventory.go" \
  "$work_dir/tools/sourcepolicy/"
cp "$root/docs/contracts/governed_url_reference_v1.json" \
  "$root/docs/contracts/cel_struct_001.json" \
  "$root/docs/contracts/cel_struct_003.json" \
  "$root/docs/contracts/cel_struct_004a.json" \
  "$root/docs/contracts/cel_struct_004b.json" \
  "$root/docs/contracts/cel_struct_004c.json" \
  "$root/docs/contracts/cel_struct_004d.json" \
  "$root/docs/contracts/cel_struct_004e.json" \
  "$root/docs/contracts/cel_struct_005.json" \
  "$root/docs/contracts/cel_split_001.json" \
  "$root/docs/contracts/cel_split_002.json" \
  "$root/docs/contracts/cel_split_003.json" \
  "$work_dir/docs/contracts/"

architecture_dir="$work_dir/architecture-repo"
mkdir -p "$architecture_dir"
git -C "$root" archive HEAD | tar -xf - -C "$architecture_dir"
cp "$root/.golangci.yml" "$architecture_dir/.golangci.yml"
cp "$root/.github/scripts/depguardcheck.sh" \
  "$root/.github/scripts/policycheck.sh" \
  "$architecture_dir/.github/scripts/"
git -C "$architecture_dir" init -q
git -C "$architecture_dir" add .
(
  cd "$architecture_dir"
  bash .github/scripts/policycheck.sh architecture
) || {
  printf 'policy check rejected the governed architecture\n' >&2
  return 1
}
for variable in GOFLAGS GOENV; do
  set +e
  if [[ "$variable" == GOFLAGS ]]; then
    output=$(cd "$architecture_dir" &&
      GOFLAGS='-overlay=attacker.json' \
        bash .github/scripts/policycheck.sh architecture 2>&1)
  else
    output=$(cd "$architecture_dir" &&
      GOENV='attacker.env' \
        bash .github/scripts/policycheck.sh architecture 2>&1)
  fi
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted uncontrolled %s\n' "$variable" >&2
    return 1
  }
  grep -Fq "Uncontrolled Go policy environment: $variable" <<<"$output" || {
    printf 'policy check did not own the %s rejection:\n%s\n' \
      "$variable" "$output" >&2
    return 1
  }
done
set +e
CELESTIA_DEPGUARD_BOUNDED=1 CELESTIA_DEPGUARD_DEADLINE_FIXTURE=1 \
  bash "$architecture_dir/.github/scripts/depguardcheck.sh"
status=$?
set -e
[[ "$status" -eq 124 ]] || {
  printf 'depguard deadline fixture returned %s, expected 124\n' "$status" >&2
  return 1
}
depguard_cancel_dir="$work_dir/depguard-cancel"
mkdir -p "$depguard_cancel_dir"
TMPDIR="$depguard_cancel_dir" CELESTIA_DEPGUARD_DEADLINE_FIXTURE=1 \
  bash "$architecture_dir/.github/scripts/depguardcheck.sh" &
depguard_wrapper=$!
depguard_deadline_root=
for _ in 1 2 3 4 5; do
  for candidate in "$depguard_cancel_dir"/celestia-depguard-deadline.*; do
    if [[ -f "$candidate/child.pid" && -f "$candidate/watchdog.pid" ]]; then
      depguard_deadline_root=$candidate
      break 2
    fi
  done
  sleep 1
done
[[ -n "$depguard_deadline_root" ]] || {
  kill -TERM "$depguard_wrapper" 2>/dev/null || true
  wait "$depguard_wrapper" 2>/dev/null || true
  printf 'depguard cancellation fixture did not publish owned processes\n' >&2
  return 1
}
depguard_child=$(cat "$depguard_deadline_root/child.pid")
depguard_watchdog=$(cat "$depguard_deadline_root/watchdog.pid")
kill -TERM "$depguard_wrapper"
set +e
wait "$depguard_wrapper"
status=$?
set -e
[[ "$status" -eq 143 ]] || {
  printf 'cancelled depguard wrapper returned %s, expected 143\n' "$status" >&2
  return 1
}
for pid in "$depguard_child" "$depguard_watchdog"; do
  if kill -0 "$pid" 2>/dev/null; then
    printf 'cancelled depguard wrapper left process %s alive\n' "$pid" >&2
    return 1
  fi
done
[[ ! -e "$depguard_deadline_root" ]] || {
  printf 'cancelled depguard wrapper retained deadline state\n' >&2
  return 1
}
if ! command -v taskkill.exe >/dev/null 2>&1; then
  depguard_descendants="$work_dir/depguard-descendants"
  status=0
  CELESTIA_DEPGUARD_BOUNDED=1 CELESTIA_DEPGUARD_DEADLINE_FIXTURE=1 \
    CELESTIA_DEPGUARD_DESCENDANT_FILE="$depguard_descendants" \
    bash "$architecture_dir/.github/scripts/depguardcheck.sh" >/dev/null 2>&1 || status=$?
  [[ "$status" -eq 124 ]] || {
    printf 'depguard descendant fixture returned %s, expected 124\n' "$status" >&2
    return 1
  }
  while IFS= read -r pid; do
    if kill -0 "$pid" 2>/dev/null; then
      printf 'depguard deadline left descendant %s alive\n' "$pid" >&2
      return 1
    fi
  done <"$depguard_descendants"
fi
mkdir -p "$architecture_dir/worker/rogue"
printf 'package rogue\n' >"$architecture_dir/worker/rogue/main.go"
git -C "$architecture_dir" add worker/rogue/main.go
set +e
output=$(cd "$architecture_dir" &&
  bash .github/scripts/policycheck.sh architecture 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted an undeclared worker package\n' >&2
  return 1
}
grep -Fq 'worker/rogue/main.go: Go package is not declared' <<<"$output" || {
  printf 'policy output omitted the architecture diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}
git -C "$architecture_dir" rm -q --cached worker/rogue/main.go
rm -f -- "$architecture_dir/worker/rogue/main.go"
rmdir "$architecture_dir/worker/rogue"
printf '\nvar verificationAttemptDrift = 1\n' \
  >>"$architecture_dir/internal/operation/urlreference/attempt/contract.go"
set +e
output=$(cd "$architecture_dir" &&
  bash .github/scripts/policycheck.sh architecture 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted attempt declaration drift\n' >&2
  return 1
}
grep -Fq 'internal/operation/urlreference/attempt: source inventory differs:' \
  <<<"$output" || {
  printf 'policy output omitted the attempt inventory diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}
git -C "$architecture_dir" checkout -- \
  internal/operation/urlreference/attempt/contract.go
printf 'default 90\ncache-max-age-minutes 0\npackage celestia.research/coverage/tools/sourcepolicy 0\n' \
  >"$work_dir/.github/.coverage"
cat >"$work_dir/go.mod" <<'EOF'
module celestia.research/coverage

go 1.26.5

require (
	github.com/BurntSushi/toml v1.6.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.38.0
	golang.org/x/sys v0.47.0
	golang.org/x/tools v0.48.0
	mvdan.cc/sh/v3 v3.13.1
)

require golang.org/x/sync v0.22.0 // indirect
EOF
awk '
  $1 == "github.com/BurntSushi/toml" &&
    ($2 == "v1.6.0" || $2 == "v1.6.0/go.mod") ||
  $1 == "github.com/go-quicktest/qt" &&
    ($2 == "v1.101.0" || $2 == "v1.101.0/go.mod") ||
  $1 == "github.com/google/go-cmp" &&
    ($2 == "v0.7.0" || $2 == "v0.7.0/go.mod") ||
  $1 == "github.com/kr/pretty" &&
    ($2 == "v0.3.1" || $2 == "v0.3.1/go.mod") ||
  $1 == "github.com/kr/text" &&
    ($2 == "v0.2.0" || $2 == "v0.2.0/go.mod") ||
  $1 == "github.com/rogpeppe/go-internal" &&
    ($2 == "v1.14.1" || $2 == "v1.14.1/go.mod") ||
  $1 == "golang.org/x/mod" &&
    ($2 == "v0.38.0" || $2 == "v0.38.0/go.mod") ||
  $1 == "golang.org/x/sync" &&
    ($2 == "v0.22.0" || $2 == "v0.22.0/go.mod") ||
  $1 == "golang.org/x/sys" &&
    ($2 == "v0.47.0" || $2 == "v0.47.0/go.mod") ||
  $1 == "golang.org/x/tools" &&
    ($2 == "v0.48.0" || $2 == "v0.48.0/go.mod") ||
  $1 == "go.yaml.in/yaml/v3" &&
    ($2 == "v3.0.5" || $2 == "v3.0.5/go.mod") ||
  $1 == "mvdan.cc/sh/v3" &&
    ($2 == "v3.13.1" || $2 == "v3.13.1/go.mod")
' "$root/go.sum" >"$work_dir/go.sum"
LC_ALL=C sort "$work_dir/go.sum" >"$work_dir/go.sum.sorted"
mv "$work_dir/go.sum.sorted" "$work_dir/go.sum"
cat >"$work_dir/xsys_fixture_windows.go" <<'EOF'
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

//go:build windows

package fixture

import _ "golang.org/x/sys/windows"
EOF
git -C "$work_dir" init -q
for workspace_file in go.work go.work.sum; do
  printf 'fixture\n' >"$work_dir/$workspace_file"
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh workspace 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted repository %s\n' "$workspace_file" >&2
    return 1
  }
  grep -Fq "$workspace_file: Go workspace files are prohibited" \
    <<<"$output" || {
    printf 'policy output omitted the Go workspace diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- "$work_dir/$workspace_file"
done
(
  cd "$work_dir"
  bash .github/scripts/policycheck.sh manifest
) || {
  printf 'policy check rejected the reviewed governed manifest\n' >&2
  return 1
}
mkdir -p "$work_dir/config-bin"
(
  cd "$work_dir"
  go build -o "$work_dir/config-bin/sourcepolicy" ./tools/sourcepolicy
)
for manifest in governed_url_reference_v1.json cel_struct_001.json \
  cel_struct_003.json cel_struct_004a.json cel_struct_004b.json \
  cel_struct_004c.json cel_struct_004d.json cel_struct_004e.json \
  cel_struct_005.json cel_split_001.json cel_split_002.json \
  cel_split_003.json; do
  printf '\n' >>"$work_dir/docs/contracts/$manifest"
  set +e
  output=$(cd "$work_dir" &&
    "$work_dir/config-bin/sourcepolicy" manifest 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted changed manifest %s\n' "$manifest" >&2
    return 1
  }
  grep -Fq 'governed manifest differs from its reviewed form' <<<"$output" || {
    printf 'policy output omitted manifest drift for %s:\n%s\n' \
      "$manifest" "$output" >&2
    return 1
  }
  cp "$root/docs/contracts/$manifest" "$work_dir/docs/contracts/"
  rm -- "$work_dir/docs/contracts/$manifest"
  set +e
  output=$(cd "$work_dir" &&
    "$work_dir/config-bin/sourcepolicy" manifest 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted missing manifest %s\n' "$manifest" >&2
    return 1
  }
  cp "$root/docs/contracts/$manifest" "$work_dir/docs/contracts/"
done
cat >"$work_dir/.git/info/exclude" <<'EOF'
/config-bin/
/lint-*/
/linter-policy/
/platform-bin/
/repo/
/rust/
/type-assertion/
EOF
if [[ "$(go env GOOS)" != windows ]] &&
  command -v mkfifo >/dev/null 2>&1; then
  printf '%s\n' 'package fixture' >"$work_dir/fifo.go"
  git -C "$work_dir" add -- fifo.go
  rm -- "$work_dir/fifo.go"
  mkfifo "$work_dir/fifo.go"
  (
    cd "$work_dir"
    "$work_dir/config-bin/sourcepolicy" suppressions \
      >"$work_dir/fifo-output" 2>&1
  ) &
  fifo_pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$fifo_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$fifo_pid" 2>/dev/null; then
    terminate_child "$fifo_pid"
    printf 'source policy blocked while opening a FIFO\n' >&2
    return 1
  fi
  set +e
  wait "$fifo_pid"
  status=$?
  set -e
  fifo_pid=
  [[ "$status" -ne 0 ]] || {
    printf 'source policy accepted a FIFO\n' >&2
    return 1
  }
  grep -Fq 'source file is not a bounded regular file' \
    "$work_dir/fifo-output" || {
    printf 'source policy omitted the FIFO diagnostic\n' >&2
    return 1
  }
  rm -- "$work_dir/fifo.go" "$work_dir/fifo-output"
  git -C "$work_dir" reset -q -- fifo.go
fi
if git -C "$work_dir" ls-files -co --exclude-standard |
  grep -Eq '^((lint-|linter-policy|platform-bin|repo|rust|type-assertion)/)'; then
  printf 'coverage fixture inventory includes generated verifier state\n' >&2
  return 1
fi
{
  printf '%s\n' '// Code generated by fixture. DO NOT EDIT.'
  awk 'BEGIN { for (line = 0; line < 801; line++) print "// fixture" }'
} >"$work_dir/-generated.go"
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh source-files 2>&1)
status=$?
set -e
[[ "$status" -eq 0 ]] || {
  printf 'policy check rejected an option-like generated filename:\n%s\n' \
    "$output" >&2
  return 1
}
rm -- "$work_dir/-generated.go"

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

cat >"$work_dir/ignored_test.rs" <<'EOF'
#[test]
#[ignore]
fn ignored() {}
EOF
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh test-skips 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted an ignored Rust test\n' >&2
  return 1
}
grep -Fq 'Rust tests must not ignore cases' <<<"$output" || {
  printf 'policy output omitted the ignored-test failure:\n%s\n' \
    "$output" >&2
  return 1
}
rm -- "$work_dir/ignored_test.rs"

mkdir -p "$work_dir/worker/url-reference/src"
mkdir -p "$work_dir/worker/qualification-fixtures"
cat >"$work_dir/Cargo.toml" <<'EOF'
[workspace]
members = ["worker/url-reference"]
exclude = ["worker/qualification-fixtures"]
EOF
cat >"$work_dir/worker/url-reference/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.0.0"
edition = "2024"
EOF
cat >"$work_dir/worker/qualification-fixtures/Cargo.toml" <<'EOF'
[package]
name = "qualification-fixture"
version = "0.0.0"
edition = "2024"
EOF
cat >"$work_dir/worker/url-reference/src/lib.rs" <<'EOF'
/// ```
/// use std::os::unix::process::CommandExt;
/// let _ = std::process::Command::new("true").exec();
/// assert!(false);
/// ```
pub fn documented() {}
EOF
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh suppressions 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted a Cargo library target\n' >&2
  return 1
}
grep -Fq 'Cargo library targets are prohibited' \
  <<<"$output" || {
  printf 'policy output omitted the Cargo library target:\n%s\n' \
    "$output" >&2
  return 1
}
rm -- \
  "$work_dir/Cargo.toml" \
  "$work_dir/worker/url-reference/Cargo.toml" \
  "$work_dir/worker/url-reference/src/lib.rs" \
  "$work_dir/worker/qualification-fixtures/Cargo.toml"

cat >"$work_dir/ignored_test.rs" <<'EOF'
#[test]
#[cfg_attr(all(), ignore)]
fn ignored() {}
EOF
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh test-skips 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted a conditionally ignored Rust test\n' >&2
  return 1
}
rm -- "$work_dir/ignored_test.rs"

cat >"$work_dir/included_test.rs" <<'EOF'
use std::include as load;

load!("skipped.inc");
EOF
cat >"$work_dir/path_test.rs" <<'EOF'
#[path = "skipped.inc"]
mod skipped;
EOF
cat >"$work_dir/forwarded_test.rs" <<'EOF'
macro_rules! make_test {
	($attribute:meta) => {
		#[test]
		#[$attribute]
		fn generated() {}
	};
}

make_test!(ignore);
EOF
cat >"$work_dir/skipped.inc" <<'EOF'
#[test]
#[ignore]
fn ignored() {}
EOF
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh test-skips 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted Rust source expansion\n' >&2
  return 1
}
grep -Fq 'Rust include! is prohibited' <<<"$output" || {
  printf 'policy output omitted the Rust include failure:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Fq 'Rust path attributes are prohibited' <<<"$output" || {
  printf 'policy output omitted the Rust path failure:\n%s\n' \
    "$output" >&2
  return 1
}
rm -- \
  "$work_dir/included_test.rs" \
  "$work_dir/path_test.rs" \
  "$work_dir/forwarded_test.rs" \
  "$work_dir/skipped.inc"

printf '%s%s\n' '// #no' 'sec -- broad' >"$work_dir/broad_suppression.go"
printf '%s%s\n' '//no' 'lint -- broad' >"$work_dir/broad_nolint.go"
printf '%s%s\n' '//no' 'lint:all -- reasoned blanket suppression' \
  >"$work_dir/reasoned_broad_nolint.go"
printf '%s%s\n' '# shell' 'check disable=SC2329' \
  >"$work_dir/broad_shellcheck.sh"
printf '%s%s\n' '#shell' 'check disable=SC2086' \
  >"$work_dir/compact_shellcheck.sh"
printf '%s\n' "printf '%s\\n' '# shellcheck disable=SC2086'" \
  >"$work_dir/shellcheck_literal.sh"
cat >"$work_dir/shellcheck_data.sh" <<'EOF'
cat <<'PAYLOAD'
# shellcheck disable=SC2086
PAYLOAD
printf '%s\n' "multiline
# shellcheck disable=SC2086"
EOF
printf '%s%s\n' '#[al' 'low(clippy::needless_pass_by_value)]' \
  >"$work_dir/broad_clippy.rs"
printf '%s%s\n' '#[al' \
  'low(clippy::all, reason = "reasoned blanket suppression")]' \
  >"$work_dir/reasoned_broad_clippy.rs"
printf '%s%s\n' '#![al' 'low(clippy::all)]' \
  >"$work_dir/inner_broad_clippy.rs"
printf '%s%s\n' '#![ex' 'pect(clippy::all)]' \
  >"$work_dir/inner_broad_expect.rs"
printf '%s\n' \
  "macro_rules! lint { (\$level:ident) => { #[\$level(clippy::all)] fn f() {} } }" \
  >"$work_dir/dynamic_attribute.rs"
cat >"$work_dir/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.0.0"
edition = "2024"

[lib]
doctest = false

[profile.test]
debug-assertions = false

[dependencies]
fixture = { version = "1", optional = true }

[patch.crates-io]
fixture = { path = "../fixture" }

[lints.rustdoc]
broken_intra_doc_links = "allow"
EOF
mkdir -p "$work_dir/.cargo"
cat >"$work_dir/.cargo/config.toml" <<'EOF'
include = ["hostile.toml"]
paths = ["../override"]

[alias]
clippy = "bypass"

[build]
rustflags = ["@args.txt"]
rustc-wrapper = "wrapper.exe"

[target.x86_64-pc-windows-msvc]
linker = "linker.exe"

[profile.test]
debug-assertions = false
EOF
cat >"$work_dir/.cargo/hostile.toml" <<'EOF'
[build]
rustflags = ["--cap-lints=allow"]
EOF
printf '%s\n' '--cap-lints' 'allow' >"$work_dir/args.txt"
head -c 1048577 /dev/zero | tr '\0' x >"$work_dir/oversized.sh"
{
  printf '%s%s\n' '#[al' 'low('
  printf '%s\n' '    clippy::all,'
  printf '%s\n' '    reason = "reasoned blanket suppression"'
  printf '%s\n' ')]'
} >"$work_dir/reasoned_broad_multiline_clippy.rs"
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh suppressions 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted hostile suppression fixtures\n' >&2
  return 1
}
if grep -Eq 'shellcheck_(literal|data)\.sh' <<<"$output"; then
  printf 'policy check treated a shell string as a suppression:\n%s\n' \
    "$output" >&2
  return 1
fi
for diagnostic in \
  'invalid gosec suppression' \
  'invalid golangci-lint suppression' \
  'invalid ShellCheck suppression' \
  'invalid Clippy suppression' \
  'dynamic Rust attributes are prohibited' \
  'Cargo library targets are prohibited' \
  'optional Cargo dependencies require an explicit test matrix' \
  'Cargo profile overrides are prohibited' \
  'Cargo lint allowances are prohibited' \
  'Cargo source override is prohibited' \
  'Cargo rustflags are not approved' \
  'Cargo execution override is prohibited' \
  'source file exceeds 1048576 bytes'; do
  grep -Fq "$diagnostic" <<<"$output" || {
    printf 'policy output omitted %s:\n%s\n' "$diagnostic" "$output" >&2
    return 1
  }
done
rm -- \
  "$work_dir/broad_suppression.go" \
  "$work_dir/broad_nolint.go" \
  "$work_dir/reasoned_broad_nolint.go" \
  "$work_dir/broad_shellcheck.sh" \
  "$work_dir/compact_shellcheck.sh" \
  "$work_dir/broad_clippy.rs" \
  "$work_dir/reasoned_broad_clippy.rs" \
  "$work_dir/inner_broad_clippy.rs" \
  "$work_dir/inner_broad_expect.rs" \
  "$work_dir/dynamic_attribute.rs" \
  "$work_dir/reasoned_broad_multiline_clippy.rs" \
  "$work_dir/Cargo.toml" \
  "$work_dir/.cargo/config.toml" \
  "$work_dir/.cargo/hostile.toml" \
  "$work_dir/args.txt" \
  "$work_dir/oversized.sh"
rmdir -- "$work_dir/.cargo"

{
  printf '%s%s\n' '// #no' 'sec G103 -- narrow native boundary'
  printf '%s%s\n' '//no' 'lint:errcheck -- checked by an owning wrapper'
} >"$work_dir/valid_suppressions.go"
printf '%s%s\n' \
  '# shell' 'check disable=SC2329 # Invoked by a registered trap' \
  >"$work_dir/valid_suppressions.sh"
printf '%s%s\n' \
  '#[al' 'low(clippy::needless_pass_by_value, reason = "FFI owns the value")]' \
  >"$work_dir/valid_suppressions.rs"
cat >"$work_dir/Cargo.toml" <<'EOF'
[workspace]
members = ["worker/url-reference"]
exclude = ["worker/qualification-fixtures"]
EOF
cat >"$work_dir/worker/url-reference/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.0.0"
edition = "2024"
EOF
cat >"$work_dir/worker/qualification-fixtures/Cargo.toml" <<'EOF'
[package]
name = "qualification-fixture"
version = "0.0.0"
edition = "2024"
EOF
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh suppressions 2>&1) || {
  printf 'policy check rejected narrow suppressions:\n%s\n' "$output" >&2
  return 1
}
rm -- \
  "$work_dir/valid_suppressions.go" \
  "$work_dir/valid_suppressions.sh" \
  "$work_dir/valid_suppressions.rs" \
  "$work_dir/Cargo.toml" \
  "$work_dir/worker/url-reference/Cargo.toml" \
  "$work_dir/worker/qualification-fixtures/Cargo.toml"

fake_bin="$work_dir/fake-bin"
real_git=$(command -v git)
mkdir -p "$fake_bin"
cat >"$fake_bin/git" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "${FAIL_GIT_COMMAND:-}" ]]; then
exit 2
fi
exec "$REAL_GIT" "$@"
EOF
chmod +x "$fake_bin/git"
set +e
output=$(
  cd "$work_dir" &&
    CELESTIA_GIT_BIN="$fake_bin/git" FAIL_GIT_COMMAND=grep \
      REAL_GIT="$real_git" \
      bash .github/scripts/policycheck.sh markers 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check ignored a failed scanner\n' >&2
  return 1
}
grep -Fq 'git grep failed while enforcing repository policy' <<<"$output" || {
  printf 'policy output omitted the scanner failure:\n%s\n' "$output" >&2
  return 1
}
set +e
output=$(
  cd "$work_dir" &&
    CELESTIA_GIT_BIN="$fake_bin/git" FAIL_GIT_COMMAND=ls-files \
      REAL_GIT="$real_git" \
      bash .github/scripts/modcheck.sh diff 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'module check ignored a failed source inventory\n' >&2
  return 1
}
grep -Fq 'Failed to inventory module inputs' <<<"$output" || {
  printf 'module output omitted the inventory failure:\n%s\n' \
    "$output" >&2
  return 1
}
)

main
