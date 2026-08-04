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
  trap 'trap - TERM; wait 2>/dev/null || true; exit 143' TERM
  if [[ -n "${CELESTIA_DEPGUARD_DESCENDANT_FILE:-}" ]]; then
    (
      trap 'trap - TERM; wait 2>/dev/null || true; exit 143' TERM
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

prepare_suite() {
  local suite_root=$1
  mkdir -p "$suite_root"
  cp "$root/.golangci.yml" "$suite_root/.golangci.yml"
  printf '\nissues:\n  generated: disable\n' >>"$suite_root/.golangci.yml"
  printf 'module celestia.research/celestia\n\ngo %s\n' "$go_version" >"$suite_root/go.mod"
}

add_case() {
  local base
  local directory
  local importer=$3
  local imported=$4
  local message=${5:-}
  local name=$2
  local suite_root=$1
  local target

  directory=$(dirname -- "$importer")
  base=${importer##*/}
  if [[ "$base" != supervisor_windows_test.go ]]; then
    base="${name//-/_}_$base"
  fi
  importer="$directory/$base"
  mkdir -p "$suite_root/$directory"

  case "$imported" in
  celestia.research/assurance)
    if [[ ! -f "$suite_root/assurance/go.mod" ]]; then
      mkdir -p "$suite_root/assurance"
      printf 'module celestia.research/assurance\n\ngo %s\n' "$go_version" \
        >"$suite_root/assurance/go.mod"
      printf 'package assurance\n' >"$suite_root/assurance/assurance.go"
      printf '\nrequire celestia.research/assurance v0.0.0\n' \
        >>"$suite_root/go.mod"
      printf 'replace celestia.research/assurance => ./assurance\n' \
        >>"$suite_root/go.mod"
    fi
    ;;
  celestia.research/celestia/*)
    target=${imported#celestia.research/celestia/}
    mkdir -p "$suite_root/$target"
    if [[ ! -f "$suite_root/$target/target.go" ]]; then
      printf 'package fixture\n' >"$suite_root/$target/target.go"
    fi
    ;;
  esac
  cat >"$suite_root/$importer" <<EOF
package fixture

import _ "$imported"
EOF
  if [[ -n "$message" ]]; then
    printf '%s\t%s\n' "$importer" "$message" >>"$suite_root/expected"
  fi
}

run_suite() {
  local expected
  local findings
  local importer
  local line
  local message
  local output
  local status
  local suite_root=$1
  local want=$2

  set +e
  output=$(cd "$suite_root" && GOOS=windows GOARCH=amd64 \
    "$lint" run --allow-parallel-runners --enable-only=depguard \
    --config .golangci.yml ./... 2>&1)
  status=$?
  set -e
  output=${output//\\//}
  if [[ "$want" == pass ]]; then
    if [[ "$status" -ne 0 ]]; then
      printf 'depguard rejected an allowed import:\n%s\n' "$output" >&2
      return 1
    fi
    return
  fi
  if [[ "$status" -eq 0 ]]; then
    printf 'depguard accepted forbidden imports\n' >&2
    return 1
  fi
  while IFS=$'\t' read -r importer message; do
    line=$(grep -F "$importer:" <<<"$output" || true)
    if [[ "$line" != *"$message"* ]] || [[ $(wc -l <<<"$line") -ne 1 ]]; then
      printf '%s lacked its forbidden-import diagnostic:\n%s\n' \
        "$importer" "$output" >&2
      return 1
    fi
  done <"$suite_root/expected"
  findings=$(grep -c '(depguard)' <<<"$output" || true)
  expected=$(wc -l <"$suite_root/expected")
  findings=${findings//[[:space:]]/}
  expected=${expected//[[:space:]]/}
  if [[ "$findings" -ne "$expected" ]]; then
    printf 'depguard produced %s findings, want %s:\n%s\n' \
      "$findings" "$expected" "$output" >&2
    return 1
  fi
}

allowed="$work/allowed"
forbidden="$work/forbidden"
prepare_suite "$allowed"
prepare_suite "$forbidden"

add_case "$allowed" production-allow internal/example/example.go fmt
add_case "$forbidden" production-reject internal/example/example.go \
  celestia.research/celestia/tools/sourcepolicy \
  'Production runtime must not import repository tools'
add_case "$forbidden" production-assurance-reject internal/example/example.go \
  celestia.research/assurance \
  'Production must not import Assurance'
add_case "$forbidden" production-worker-reject internal/example/example.go \
  celestia.research/celestia/worker/url-reference \
  'Production runtime must not import worker source'
add_case "$allowed" execution-allow internal/execution/supervision/example.go fmt
add_case "$forbidden" execution-reject internal/execution/supervision/example.go \
  celestia.research/celestia/internal/operation/urlreference \
  'execution packages must not import operation packages'
add_case "$forbidden" execution-test-reject internal/execution/supervision/rogue_test.go \
  celestia.research/celestia/internal/operation/urlreference \
  'execution packages must not import operation packages'
add_case "$allowed" execution-integration-allow \
  internal/execution/supervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/operation/urlreference/admission
add_case "$forbidden" execution-integration-reject \
  internal/execution/supervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/operation/urlreference \
  'supervision qualification test imports only declared dependencies'
add_case "$allowed" command-allow cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference
add_case "$forbidden" command-reject cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference/transform \
  'commands import declared operation roots only'
add_case "$allowed" operation-allow internal/operation/urlreference/example.go \
  celestia.research/celestia/internal/operation/urlreference/admission
add_case "$forbidden" operation-reject internal/operation/urlreference/example.go \
  celestia.research/celestia/internal/operation/other \
  'operation roots import only their own declared subpackages'
add_case "$allowed" attempt-allow internal/operation/urlreference/attempt/example.go \
  celestia.research/celestia/internal/operation/urlreference/protocol
add_case "$forbidden" attempt-reject internal/operation/urlreference/attempt/example.go \
  celestia.research/celestia/internal/execution/supervision \
  'attempt evidence imports only lower URL-reference owners'
add_case "$allowed" admission-allow internal/operation/urlreference/admission/example.go \
  celestia.research/celestia/internal/operation/urlreference/protocol
add_case "$forbidden" admission-reject internal/operation/urlreference/admission/example.go \
  celestia.research/celestia/internal/operation/urlreference/attempt \
  'admission imports only protocol and transformation'
add_case "$allowed" protocol-allow internal/operation/urlreference/protocol/example.go \
  celestia.research/celestia/internal/operation/urlreference/transform
add_case "$forbidden" protocol-reject \
  internal/operation/urlreference/protocol/example.go \
  celestia.research/celestia/internal/operation/urlreference/admission \
  'protocol imports only transformation'
add_case "$allowed" transform-allow internal/operation/urlreference/transform/example.go fmt
add_case "$forbidden" transform-reject internal/operation/urlreference/transform/example.go \
  celestia.research/celestia/internal/execution/supervision \
  'transformation must not import other Production internals'

run_suite "$allowed" pass
run_suite "$forbidden" reject
