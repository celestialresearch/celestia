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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$script_dir/../../.." && pwd)
script_dir_path="$script_dir/source_policy"
script_repo=$root
script_prefix=.github/scripts/verification/source_policy
scripts=(
  setup.sh
  architecture.sh
  manifests.sh
  source_bounds.sh
  go_execution.sh
  rust_cargo.sh
  suppressions.sh
  scanner_failure.sh
)

fixture_mode=${1:-}
fixture_path="$script_dir/fixture.sh"
snapshot_checkpoint=
group_probe=
case "$fixture_mode" in
"") ;;
--fixture)
  script_dir_path=${CELESTIA_SOURCE_POLICY_SCRIPT_DIR:?}
  script_repo=${CELESTIA_SOURCE_POLICY_SCRIPT_REPO:?}
  script_prefix=${CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX:?}
  fixture_path=${CELESTIA_SOURCE_POLICY_FIXTURE_PATH:-$fixture_path}
  snapshot_checkpoint=${CELESTIA_SOURCE_POLICY_SNAPSHOT_CHECKPOINT:-}
  group_probe=${CELESTIA_SOURCE_POLICY_GROUP_PROBE:-}
  ;;
*)
  printf 'Usage: source_policy_test.sh [--fixture]\n' >&2
  exit 2
  ;;
esac
if [[ "$fixture_mode" != --fixture ]] &&
  [[ -n "${CELESTIA_SOURCE_POLICY_SCRIPT_DIR+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SCRIPT_REPO+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_FIXTURE_PATH+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SNAPSHOT_CHECKPOINT+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_GROUP_PROBE+x}" ]]; then
  printf 'source-policy script overrides require fixture mode\n' >&2
  exit 2
fi
if [[ -n "$group_probe" ]] &&
  [[ -L "$group_probe" || ! -f "$group_probe" || ! -x "$group_probe" ]]; then
  printf 'source-policy group probe is unavailable\n' >&2
  exit 2
fi

# shellcheck source=.github/scripts/verification/fixture.sh
source "$script_dir/fixture.sh"

active_script_pid=
pending_signal=
starting_script=

active_script_running() {
  kill -0 -- "-$active_script_pid" 2>/dev/null ||
    kill -0 "$active_script_pid" 2>/dev/null
}

active_script_group_running() {
  if [[ -n "$group_probe" ]]; then
    "$group_probe" "$active_script_pid"
    return
  fi
  kill -0 -- "-$active_script_pid" 2>/dev/null
}

stop_completed_group() {
  local attempt

  active_script_group_running || return 0
  kill -TERM -- "-$active_script_pid" 2>/dev/null || true
  attempt=0
  if [[ -n "$group_probe" ]]; then
    attempt=40
  fi
  while active_script_group_running && ((attempt < 40)); do
    sleep 0.05
    attempt=$((attempt + 1))
  done
  if active_script_group_running; then
    kill -KILL -- "-$active_script_pid" 2>/dev/null || true
    attempt=0
    if [[ -n "$group_probe" ]]; then
      attempt=40
    fi
    while active_script_group_running && ((attempt < 40)); do
      sleep 0.05
      attempt=$((attempt + 1))
    done
  fi
  if active_script_group_running; then
    printf 'source-policy script retained a live process group\n' >&2
    return 2
  fi
  return 1
}

finish_source_policy() {
  local cleanup_status
  local status=$1
  local work_dir=$2

  trap - EXIT HUP INT TERM
  if [[ -n "$active_script_pid" ]]; then
    set +e
    stop_completed_group
    cleanup_status=$?
    set -e
    if [[ "$cleanup_status" -eq 2 ]]; then
      printf 'source-policy process-group cleanup failed during exit\n' >&2
      status=1
    else
      active_script_pid=
    fi
  fi
  set +e
  cleanup_verification "$work_dir"
  cleanup_status=$?
  set -e
  if [[ "$cleanup_status" -ne 0 ]]; then
    printf 'source-policy temporary cleanup failed during exit\n' >&2
    status=1
  fi
  exit "$status"
}

stop_active_script() {
  local attempt
  local signal_status=$1

  if [[ -z "$active_script_pid" && -n "$starting_script" ]]; then
    pending_signal=$signal_status
    return
  fi
  trap - HUP INT TERM
  if [[ -n "$active_script_pid" ]]; then
    kill -TERM -- "-$active_script_pid" 2>/dev/null ||
      kill -TERM "$active_script_pid" 2>/dev/null || true
    attempt=0
    while active_script_running && ((attempt < 40)); do
      sleep 0.05
      attempt=$((attempt + 1))
    done
    kill -KILL -- "-$active_script_pid" 2>/dev/null ||
      kill -KILL "$active_script_pid" 2>/dev/null || true
    wait "$active_script_pid" 2>/dev/null || true
    set +e
    stop_completed_group
    attempt=$?
    set -e
    if [[ "$attempt" -ne 2 ]]; then
      active_script_pid=
    fi
  fi
  exit "$signal_status"
}

run_source_policy_script() {
  local cleanup_status
  local path=$1
  local result
  local work_dir=$2

  starting_script=1
  set -m
  "$path" "$root" "$work_dir" &
  active_script_pid=$!
  set +m
  starting_script=
  if [[ -n "$pending_signal" ]]; then
    result=$pending_signal
    pending_signal=
    stop_active_script "$result"
  fi
  set +e
  wait "$active_script_pid"
  result=$?
  stop_completed_group
  cleanup_status=$?
  set -e
  if [[ "$cleanup_status" -ne 2 ]]; then
    active_script_pid=
  fi
  if [[ "$cleanup_status" -eq 2 ]]; then
    printf 'source-policy script cleanup failed: %s\n' "${path##*/}" >&2
    finish_source_policy 1 "$work_dir"
  fi
  if [[ "$cleanup_status" -ne 0 && "$result" -eq 0 ]]; then
    printf 'source-policy script left descendant processes: %s\n' \
      "${path##*/}" >&2
    return 1
  fi
  return "$result"
}

reject_extra_source() (
  local fixture_root
  local fixture_work
  local output
  local probe
  local status

  probe=$(new_verification_work verification-source-inventory)
  trap 'cleanup_verification "$probe"' EXIT
  fixture_root="$probe/root"
  fixture_work="$probe/work"
  mkdir -p "$fixture_root" "$fixture_work"
  git -C "$root" archive HEAD | tar -xf - -C "$fixture_root"
  printf 'package main\n' >"$fixture_root/tools/sourcepolicy/unreviewed.go"
  git -C "$fixture_root" init -q
  git -C "$fixture_root" add .
  set +e
  output=$("$script_dir_path/setup.sh" "$fixture_root" "$fixture_work" 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'source-policy setup accepted unreviewed source\n' >&2
    return 1
  }
  grep -Fq 'source-policy fixture inventory differs from tracked source' \
    <<<"$output" || {
    printf 'source-policy setup omitted the source inventory diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
)

reject_extra_contract() (
  local fixture_root
  local fixture_work
  local output
  local probe
  local status

  probe=$(new_verification_work verification-manifest-inventory)
  trap 'cleanup_verification "$probe"' EXIT
  fixture_root="$probe/root"
  fixture_work="$probe/work"
  mkdir -p "$fixture_root" "$fixture_work"
  git -C "$root" archive HEAD | tar -xf - -C "$fixture_root"
  printf '{}\n' >"$fixture_root/docs/contracts/unreviewed.json"
  git -C "$fixture_root" init -q
  git -C "$fixture_root" add .
  set +e
  output=$("$script_dir_path/setup.sh" "$fixture_root" "$fixture_work" 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'source-policy setup accepted an unreviewed contract\n' >&2
    return 1
  }
  grep -Fq \
    'governed manifest fixture inventory differs from tracked contracts' \
    <<<"$output" || {
    printf 'source-policy setup omitted the contract inventory diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
)

snapshot_script() {
  local binding=$1
  local kind=$2
  local path=$3
  local source_size
  local target=$4
  local target_size

  [[ ! -L "$path" && -f "$path" ]] || return 1
  cat -- "$path" >"$binding" || return 1
  source_size=$(wc -c <"$binding") || return 1
  [[ ! -L "$path" && -f "$path" ]] || return 1
  [[ "$(wc -c <"$path")" -eq "$source_size" ]] || return 1
  cmp -s -- "$path" "$binding" || return 1
  if [[ -n "$snapshot_checkpoint" ]]; then
    "$snapshot_checkpoint" "$kind" "$path" || return 1
  fi
  [[ ! -L "$path" && -f "$path" ]] || return 1
  [[ "$(wc -c <"$path")" -eq "$source_size" ]] || return 1
  cmp -s -- "$path" "$binding" || return 1
  cat -- "$binding" >"$target" || return 1
  target_size=$(wc -c <"$target") || return 1
  [[ "$target_size" -eq "$source_size" ]] || return 1
  cmp -s -- "$binding" "$target"
}

main() {
  local binding_dir
  local executed
  local fixture_hash
  local fixture_size
  local index
  local mode
  local path
  local script
  local snapshot
  local snapshot_dir
  local -a snapshot_hashes=()
  local -a snapshot_sizes=()
  local work_dir

  work_dir=$(new_verification_work verification-source-policy)
  executed="$work_dir/executed"
  trap 'finish_source_policy "$?" '"$(printf '%q' "$work_dir")" EXIT
  trap '[[ $- != *e* ]] || printf "verification-source-policy failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
  trap 'stop_active_script 129' HUP
  trap 'stop_active_script 130' INT
  trap 'stop_active_script 143' TERM

  printf '%s\n' "${scripts[@]/#/$script_prefix\/}" | LC_ALL=C sort \
    >"$work_dir/expected-scripts"
  if ! find "$script_dir_path" -name '*.sh' -print0 \
    >"$work_dir/script-candidates"; then
    printf 'failed to inventory source-policy script entries\n' >&2
    return 1
  fi
  : >"$work_dir/available-scripts"
  while IFS= read -r -d '' path; do
    if [[ -L "$path" || ! -f "$path" ]]; then
      printf 'source-policy script is unavailable: %s\n' "$path" >&2
      return 1
    fi
    script=${path##*/}
    case "$script" in
    *$'\n'* | *$'\r'*)
      printf 'source-policy script has an unsupported name\n' >&2
      return 1
      ;;
    esac
    printf '%s\n' "$script" >>"$work_dir/available-scripts"
  done <"$work_dir/script-candidates"
  LC_ALL=C sort -o "$work_dir/available-scripts" \
    "$work_dir/available-scripts"
  if ! diff -u <(printf '%s\n' "${scripts[@]}" | LC_ALL=C sort) \
    "$work_dir/available-scripts"; then
    printf 'source-policy script inventory differs from its reviewed form\n' >&2
    return 1
  fi
  if ! git -C "$script_repo" ls-files -- "$script_prefix/*.sh" \
    | LC_ALL=C sort >"$work_dir/tracked-scripts"; then
    printf 'failed to inventory source-policy scripts\n' >&2
    return 1
  fi
  if ! diff -u "$work_dir/expected-scripts" "$work_dir/tracked-scripts"; then
    printf 'source-policy script inventory differs from its reviewed form\n' >&2
    return 1
  fi

  if [[ -z "$fixture_mode" ]]; then
    reject_extra_source
    reject_extra_contract
  fi
  snapshot_dir="$work_dir/driver"
  binding_dir="$work_dir/bindings"
  mkdir -p -- "$snapshot_dir/source_policy" "$binding_dir"
  if ! snapshot_script "$binding_dir/fixture.sh" fixture "$fixture_path" \
    "$snapshot_dir/fixture.sh"; then
    printf 'source-policy fixture changed during snapshot\n' >&2
    return 1
  fi
  fixture_size=$(wc -c <"$snapshot_dir/fixture.sh")
  fixture_hash=$(git hash-object --no-filters -- "$snapshot_dir/fixture.sh")
  for script in "${scripts[@]}"; do
    path="$script_dir_path/$script"
    mode=$(git -C "$script_repo" ls-files --stage -- "$script_prefix/$script")
    if [[ -L "$path" || ! -f "$path" || "${mode%% *}" != 100755 ]]; then
      printf 'source-policy script is unavailable: %s\n' "$script" >&2
      return 1
    fi
    snapshot="$snapshot_dir/source_policy/$script"
    if ! snapshot_script "$binding_dir/$script" script "$path" "$snapshot" ||
      ! chmod 700 -- "$snapshot"; then
      printf 'source-policy script changed during snapshot: %s\n' "$script" >&2
      return 1
    fi
    snapshot_sizes+=("$(wc -c <"$snapshot")")
    snapshot_hashes+=("$(git hash-object --no-filters -- "$snapshot")")
  done
  rm -rf -- "$binding_dir"
  index=0
  for script in "${scripts[@]}"; do
    snapshot="$snapshot_dir/source_policy/$script"
    if [[ -L "$snapshot" || ! -f "$snapshot" ]] ||
      [[ "$(wc -c <"$snapshot")" -ne "${snapshot_sizes[$index]}" ]] ||
      [[ "$(git hash-object --no-filters -- "$snapshot")" != \
        "${snapshot_hashes[$index]}" ]] ||
      [[ -L "$snapshot_dir/fixture.sh" || ! -f "$snapshot_dir/fixture.sh" ]] ||
      [[ "$(wc -c <"$snapshot_dir/fixture.sh")" -ne "$fixture_size" ]] ||
      [[ "$(git hash-object --no-filters -- \
        "$snapshot_dir/fixture.sh")" != "$fixture_hash" ]]; then
      printf 'source-policy script changed before execution: %s\n' "$script" >&2
      return 1
    fi
    run_source_policy_script "$snapshot" "$work_dir"
    printf '%s\n' "$script" >>"$executed"
    index=$((index + 1))
  done
  if ! diff -u <(printf '%s\n' "${scripts[@]}") "$executed"; then
    printf 'source-policy scripts lacked ordered execution\n' >&2
    return 1
  fi
}

main "$@"
