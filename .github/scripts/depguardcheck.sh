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

deadline_seconds=30
if [[ "${CELESTIA_DEPGUARD_DEADLINE_FIXTURE:-}" == 1 ]]; then
  deadline_seconds=1
fi
bounded=0
if [[ "${1:-}" == --celestia-depguard-bounded ]]; then
  [[ "$#" -eq 1 ]] || {
    printf 'invalid depguard bounded invocation\n' >&2
    exit 2
  }
  bounded=1
  shift
fi

terminate_tree() {
  local child
  local native_pid
  local pid=$1

  if command -v taskkill.exe >/dev/null 2>&1; then
    native_pid=$(ps 2>/dev/null | awk -v pid="$pid" \
      '$1 == pid { print $4; exit }')
    [[ "$native_pid" =~ ^[0-9]+$ ]] || {
      printf 'depguard deadline could not resolve the native process\n' >&2
      return 1
    }
    if ! taskkill.exe //PID "$native_pid" //T //F >/dev/null 2>&1; then
      kill -KILL "$pid" 2>/dev/null || true
      return 1
    fi
    return 0
  fi
  command -v pgrep >/dev/null 2>&1 || {
    printf 'depguard deadline cannot own the process tree\n' >&2
    return 1
  }
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    terminate_tree "$child"
  done
  kill -TERM "$pid" 2>/dev/null || true
  sleep 1
  kill -KILL "$pid" 2>/dev/null || true
}

terminate_owned() {
  local pid=$1

  if command -v taskkill.exe >/dev/null 2>&1; then
    terminate_tree "$pid"
    return
  fi
  kill -TERM -- "-$pid" 2>/dev/null || true
  sleep 1
  kill -KILL -- "-$pid" 2>/dev/null || true
}

cancel_bounded() {
  local owned
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "${watchdog:-}" ]]; then
    terminate_tree "$watchdog" 2>/dev/null || true
    wait "$watchdog" 2>/dev/null || true
    watchdog=
  fi
  if [[ -n "${child:-}" ]]; then
    terminate_owned "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
    child=
  fi
  for owned in $(jobs -pr); do
    terminate_tree "$owned" 2>/dev/null || true
    wait "$owned" 2>/dev/null || true
  done
  if [[ -n "${deadline_root:-}" ]]; then
    rm -rf -- "$deadline_root"
    deadline_root=
  fi
  exit "$status"
}

run_bounded() {
  local child
  local deadline_root
  local process_group
  local status
  local watchdog
  local watchdog_status=0

  if ! command -v taskkill.exe >/dev/null 2>&1 && {
    ! command -v pgrep >/dev/null 2>&1 ||
      ! command -v ps >/dev/null 2>&1
  }; then
    printf 'depguard deadline cannot own the process tree\n' >&2
    return 125
  fi

  trap 'cancel_bounded 129' HUP
  trap 'cancel_bounded 130' INT
  trap 'cancel_bounded 143' TERM
  trap 'cancel_bounded $?' EXIT
  deadline_root=$(mktemp -d "${TMPDIR:-/tmp}/celestia-depguard-deadline.XXXXXX")
  if command -v taskkill.exe >/dev/null 2>&1; then
    bash "$0" --celestia-depguard-bounded "$@" &
  else
    set -m
    bash "$0" --celestia-depguard-bounded "$@" &
    set +m
  fi
  child=$!
  if ! command -v taskkill.exe >/dev/null 2>&1 && kill -0 "$child" 2>/dev/null; then
    process_group=$(ps -o pgid= -p "$child" 2>/dev/null | tr -d '[:space:]')
    if [[ "$process_group" != "$child" ]]; then
      kill -KILL "$child" 2>/dev/null || true
      wait "$child" 2>/dev/null || true
      printf 'depguard child lacks an isolated process group\n' >&2
      return 125
    fi
  fi
  (
    elapsed=0
    while [[ "$elapsed" -lt "$deadline_seconds" ]]; do
      sleep 1
      [[ -f "$deadline_root/done" ]] && exit 0
      elapsed=$((elapsed + 1))
    done
    printf expired >"$deadline_root/expired"
    terminate_owned "$child"
  ) &
  watchdog=$!
  if [[ "${CELESTIA_DEPGUARD_DEADLINE_FIXTURE:-}" == 1 ]]; then
    printf '%s' "$child" >"$deadline_root/child.pid"
    printf '%s' "$watchdog" >"$deadline_root/watchdog.pid"
  fi

  set +e
  wait "$child"
  status=$?
  set -e
  child=
  printf '%s' "done" >"$deadline_root/done"
  if [[ -f "$deadline_root/expired" ]]; then
    wait "$watchdog" 2>/dev/null || watchdog_status=$?
    watchdog=
    rm -rf -- "$deadline_root"
    deadline_root=
    trap - EXIT HUP INT TERM
    if [[ "$watchdog_status" -ne 0 ]]; then
      printf 'depguard deadline process cleanup failed\n' >&2
      return 125
    fi
    printf 'depguard qualification exceeded %s seconds\n' "$deadline_seconds" >&2
    return 124
  fi
  wait "$watchdog" 2>/dev/null || true
  watchdog=
  rm -rf -- "$deadline_root"
  deadline_root=
  trap - EXIT HUP INT TERM
  return "$status"
}

if [[ "$bounded" -ne 1 ]]; then
  run_bounded "$@"
  exit $?
fi

if [[ "${CELESTIA_DEPGUARD_DEADLINE_FIXTURE:-}" == 1 ]]; then
  if [[ -n "${CELESTIA_DEPGUARD_DESCENDANT_FILE:-}" ]]; then
    (
      sleep 1.2
      sleep 60 &
      printf '%s\n' "$!" >>"$CELESTIA_DEPGUARD_DESCENDANT_FILE"
      wait
    ) &
    printf '%s\n' "$!" >>"$CELESTIA_DEPGUARD_DESCENDANT_FILE"
    sleep 60 &
    printf '%s\n' "$!" >>"$CELESTIA_DEPGUARD_DESCENDANT_FILE"
    wait
  fi
  exec sleep 60
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/celestia-depguard.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

lint=$(cd "$root" && go tool -n golangci-lint)
go_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")

check_case() {
  name=$1
  importer=$2
  imported=$3
  want=$4
  message=$5
  case_root="$work/$name"
  mkdir -p "$case_root/$(dirname -- "$importer")"
  cp "$root/.golangci.yml" "$case_root/.golangci.yml"
  printf 'module celestia.research/celestia\n\ngo %s\n' "$go_version" >"$case_root/go.mod"

  case "$imported" in
    celestia.research/assurance)
      mkdir -p "$case_root/assurance"
      printf 'module celestia.research/assurance\n\ngo %s\n' "$go_version" \
        >"$case_root/assurance/go.mod"
      printf 'package assurance\n' >"$case_root/assurance/assurance.go"
      printf '\nrequire celestia.research/assurance v0.0.0\n' \
        >>"$case_root/go.mod"
      printf 'replace celestia.research/assurance => ./assurance\n' \
        >>"$case_root/go.mod"
      ;;
    celestia.research/celestia/*)
      target=${imported#celestia.research/celestia/}
      mkdir -p "$case_root/$target"
      printf 'package target\n' >"$case_root/$target/target.go"
      ;;
  esac
  cat >"$case_root/$importer" <<EOF
package fixture

import _ "$imported"
EOF

  set +e
  case "$importer" in
    *_windows_test.go)
      output=$(cd "$case_root" && GOOS=windows GOARCH=amd64 \
        "$lint" run --allow-parallel-runners --enable-only=depguard \
        --config .golangci.yml ./... 2>&1)
      ;;
    *)
      output=$(cd "$case_root" && \
        "$lint" run --allow-parallel-runners --enable-only=depguard \
        --config .golangci.yml ./... 2>&1)
      ;;
  esac
  status=$?
  set -e
  if [[ "$want" == pass && "$status" -ne 0 ]]; then
    printf '%s rejected an allowed import:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  if [[ "$want" == reject ]] &&
    { [[ "$status" -eq 0 ]] || [[ "$output" != *"$message"* ]]; }; then
    printf '%s accepted a forbidden import:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
}

case_pids=
case_count=0

wait_cases() {
  local pid
  local result=0

  for pid in $case_pids; do
    if ! wait "$pid"; then
      result=1
    fi
  done
  case_pids=
  case_count=0
  return "$result"
}

run_case() {
  check_case "$@" &
  case_pids="$case_pids $!"
  case_count=$((case_count + 1))
  if [[ "$case_count" -ge 12 ]]; then
    wait_cases
  fi
}

run_case production-allow internal/example/example.go fmt pass ''
run_case production-reject internal/example/example.go \
  celestia.research/celestia/tools/sourcepolicy reject \
  'Production runtime must not import repository tools'
run_case production-assurance-reject internal/example/example.go \
  celestia.research/assurance reject \
  'Production must not import Assurance'
run_case production-worker-reject internal/example/example.go \
  celestia.research/celestia/worker/url-reference reject \
  'Production runtime must not import worker source'
run_case execution-allow internal/execution/supervision/example.go fmt pass ''
run_case execution-reject internal/execution/supervision/example.go \
  celestia.research/celestia/internal/operation/urlreference reject \
  'execution packages must not import operation packages'
run_case execution-test-reject internal/execution/supervision/rogue_test.go \
  celestia.research/celestia/internal/operation/urlreference reject \
  'execution packages must not import operation packages'
run_case execution-integration-allow \
  internal/execution/supervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/operation/urlreference/admission pass ''
run_case execution-integration-reject \
  internal/execution/supervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/operation/urlreference reject \
  'supervision qualification test imports only declared dependencies'
run_case command-allow cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference pass ''
run_case command-reject cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference/transform reject \
  'commands import declared operation roots only'
run_case operation-allow internal/operation/urlreference/example.go \
  celestia.research/celestia/internal/operation/urlreference/admission pass ''
run_case operation-reject internal/operation/urlreference/example.go \
  celestia.research/celestia/internal/operation/other reject \
  'operation roots import only their own declared subpackages'
run_case attempt-allow internal/operation/urlreference/attempt/example.go \
  celestia.research/celestia/internal/operation/urlreference/protocol pass ''
run_case attempt-reject internal/operation/urlreference/attempt/example.go \
  celestia.research/celestia/internal/execution/supervision reject \
  'attempt evidence imports only lower URL-reference owners'
run_case admission-allow internal/operation/urlreference/admission/example.go \
  celestia.research/celestia/internal/operation/urlreference/protocol pass ''
run_case admission-reject internal/operation/urlreference/admission/example.go \
  celestia.research/celestia/internal/operation/urlreference/attempt reject \
  'admission imports only protocol and transformation'
run_case protocol-allow internal/operation/urlreference/protocol/example.go \
  celestia.research/celestia/internal/operation/urlreference/transform pass ''
run_case protocol-reject \
  internal/operation/urlreference/protocol/example.go \
  celestia.research/celestia/internal/operation/urlreference/admission reject \
  'protocol imports only transformation'
run_case transform-allow internal/operation/urlreference/transform/example.go fmt pass ''
run_case transform-reject internal/operation/urlreference/transform/example.go \
  celestia.research/celestia/internal/execution/supervision reject \
  'transformation must not import other Production internals'
wait_cases
