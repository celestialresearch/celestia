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

terminate_tree() {
  local child
  local native_pid
  local pid=$1

  if command -v taskkill.exe >/dev/null 2>&1; then
    native_pid=$(ps -W 2>/dev/null | awk -v pid="$pid" \
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

run_bounded() {
  local child
  local deadline_root
  local status
  local watchdog
  local watchdog_status=0

  if ! command -v taskkill.exe >/dev/null 2>&1 &&
    ! command -v pgrep >/dev/null 2>&1; then
    printf 'depguard deadline cannot own the process tree\n' >&2
    return 125
  fi

  deadline_root=$(mktemp -d "${TMPDIR:-/tmp}/celestia-depguard-deadline.XXXXXX")
  (
    trap 'printf "%s" "done" >"$deadline_root/done"' EXIT
    CELESTIA_DEPGUARD_BOUNDED=1 bash "$0" "$@"
  ) &
  child=$!
  (
    sleep "$deadline_seconds"
    [[ -f "$deadline_root/done" ]] && exit 0
    printf expired >"$deadline_root/expired"
    terminate_tree "$child"
  ) &
  watchdog=$!

  set +e
  wait "$child"
  status=$?
  set -e
  printf '%s' "done" >"$deadline_root/done"
  if [[ -f "$deadline_root/expired" ]]; then
    wait "$watchdog" 2>/dev/null || watchdog_status=$?
    rm -rf -- "$deadline_root"
    if [[ "$watchdog_status" -ne 0 ]]; then
      printf 'depguard deadline process cleanup failed\n' >&2
      return 125
    fi
    printf 'depguard qualification exceeded %s seconds\n' "$deadline_seconds" >&2
    return 124
  fi
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  rm -rf -- "$deadline_root"
  return "$status"
}

if [[ "${CELESTIA_DEPGUARD_BOUNDED:-}" != 1 ]]; then
  run_bounded "$@"
  exit $?
fi

if [[ "${CELESTIA_DEPGUARD_DEADLINE_FIXTURE:-}" == 1 ]]; then
  sleep 60
  exit 0
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/celestia-depguard.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

lint=$(cd "$root" && go tool -n golangci-lint)
go_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")

run_case() {
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
        "$lint" run --enable-only=depguard --config .golangci.yml ./... 2>&1)
      ;;
    *)
      output=$(cd "$case_root" && \
        "$lint" run --enable-only=depguard --config .golangci.yml ./... 2>&1)
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

run_case production-allow internal/example/example.go fmt pass ''
run_case production-reject internal/example/example.go \
  celestia.research/celestia/tools/sourcepolicy reject \
  'Production runtime must not import repository tools'
run_case execution-allow internal/processsupervision/example.go fmt pass ''
run_case execution-reject internal/processsupervision/example.go \
  celestia.research/celestia/internal/urloperation reject \
  'execution packages must not import operation packages'
run_case execution-test-reject internal/processsupervision/rogue_test.go \
  celestia.research/celestia/internal/urloperation reject \
  'execution packages must not import operation packages'
run_case execution-integration-allow \
  internal/processsupervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/urladmission pass ''
run_case execution-integration-reject \
  internal/processsupervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/urloperation reject \
  'supervision qualification test imports only declared dependencies'
run_case command-allow cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference pass ''
run_case command-reject cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference/transform reject \
  'commands import declared operation roots only'
run_case operation-allow internal/urloperation/example.go \
  celestia.research/celestia/internal/urladmission pass ''
run_case operation-reject internal/urloperation/example.go \
  celestia.research/celestia/internal/operation/other reject \
  'operation roots import only their own declared subpackages'
run_case attempt-allow internal/attemptstore/example.go \
  celestia.research/celestia/internal/workerprotocolv1 pass ''
run_case attempt-reject internal/attemptstore/example.go \
  celestia.research/celestia/internal/processsupervision reject \
  'attempt evidence imports only lower URL-reference owners'
run_case final-attempt-reject \
  internal/operation/urlreference/attempt/example.go \
  celestia.research/celestia/internal/processsupervision reject \
  'attempt evidence imports only lower URL-reference owners'
run_case admission-allow internal/urladmission/example.go \
  celestia.research/celestia/internal/workerprotocolv1 pass ''
run_case admission-reject internal/urladmission/example.go \
  celestia.research/celestia/internal/attemptstore reject \
  'admission imports only protocol and transformation'
run_case final-admission-reject \
  internal/operation/urlreference/admission/example.go \
  celestia.research/celestia/internal/attemptstore reject \
  'admission imports only protocol and transformation'
run_case protocol-allow internal/workerprotocolv1/example.go \
  celestia.research/celestia/internal/urlreferencev1 pass ''
run_case protocol-reject internal/workerprotocolv1/example.go \
  celestia.research/celestia/internal/urladmission reject \
  'protocol imports only transformation'
run_case final-protocol-reject \
  internal/operation/urlreference/protocol/example.go \
  celestia.research/celestia/internal/urladmission reject \
  'protocol imports only transformation'
run_case transform-allow internal/urlreferencev1/example.go fmt pass ''
run_case transform-reject internal/urlreferencev1/example.go \
  celestia.research/celestia/internal/processsupervision reject \
  'transformation must not import other Production internals'
run_case final-transform-reject \
  internal/operation/urlreference/transform/example.go \
  celestia.research/celestia/internal/processsupervision reject \
  'transformation must not import other Production internals'
