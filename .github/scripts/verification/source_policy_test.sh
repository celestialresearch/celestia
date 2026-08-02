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
case "$fixture_mode" in
"") ;;
--fixture)
  script_dir_path=${CELESTIA_SOURCE_POLICY_SCRIPT_DIR:?}
  script_repo=${CELESTIA_SOURCE_POLICY_SCRIPT_REPO:?}
  script_prefix=${CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX:?}
  ;;
*)
  printf 'Usage: source_policy_test.sh [--fixture]\n' >&2
  exit 2
  ;;
esac
if [[ "$fixture_mode" != --fixture ]] &&
  [[ -n "${CELESTIA_SOURCE_POLICY_SCRIPT_DIR+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SCRIPT_REPO+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX+x}" ]]; then
  printf 'source-policy script overrides require fixture mode\n' >&2
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
    active_script_pid=
  fi
  exit "$signal_status"
}

run_source_policy_script() {
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
  set -e
  active_script_pid=
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

bind_script() {
  local bound
  local bound_size
  local file_size
  local path=$1

  bound=$(cat -- "$path"; printf '\034') || return 1
  bound_size=$(printf '%s' "$bound" | wc -c) || return 1
  file_size=$(wc -c <"$path") || return 1
  [[ "$bound_size" -eq "$((file_size + 1))" ]] || return 1
  printf '%s' "$bound"
}

main() {
  local bound
  local executed
  local fixture_bound
  local fixture_path
  local index
  local mode
  local path
  local script
  local snapshot
  local snapshot_dir
  local -a snapshot_bounds=()
  local work_dir

  work_dir=$(new_verification_work verification-source-policy)
  executed="$work_dir/executed"
  trap 'cleanup_verification '"$(printf '%q' "$work_dir")" EXIT
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
  mkdir -p -- "$snapshot_dir/source_policy"
  fixture_path="$script_dir/fixture.sh"
  if [[ -L "$fixture_path" || ! -f "$fixture_path" ]] ||
    ! cat -- "$fixture_path" >"$snapshot_dir/fixture.sh" ||
    [[ -L "$fixture_path" || ! -f "$fixture_path" ]] ||
    ! cmp -s -- "$fixture_path" "$snapshot_dir/fixture.sh" ||
    ! fixture_bound=$(bind_script "$snapshot_dir/fixture.sh"); then
    printf 'source-policy fixture changed during snapshot\n' >&2
    return 1
  fi
  for script in "${scripts[@]}"; do
    path="$script_dir_path/$script"
    mode=$(git -C "$script_repo" ls-files --stage -- "$script_prefix/$script")
    if [[ -L "$path" || ! -f "$path" || "${mode%% *}" != 100755 ]]; then
      printf 'source-policy script is unavailable: %s\n' "$script" >&2
      return 1
    fi
    snapshot="$snapshot_dir/source_policy/$script"
    if ! cat -- "$path" >"$snapshot" ||
      [[ -L "$path" || ! -f "$path" ]] ||
      ! cmp -s -- "$path" "$snapshot" ||
      ! chmod 700 -- "$snapshot"; then
      printf 'source-policy script changed during snapshot: %s\n' "$script" >&2
      return 1
    fi
    if ! bound=$(bind_script "$snapshot"); then
      printf 'source-policy script cannot be bound: %s\n' "$script" >&2
      return 1
    fi
    snapshot_bounds+=("$bound")
  done
  index=0
  for script in "${scripts[@]}"; do
    snapshot="$snapshot_dir/source_policy/$script"
    if [[ -L "$snapshot" || ! -f "$snapshot" ]] ||
      ! bound=$(bind_script "$snapshot") ||
      [[ "$bound" != "${snapshot_bounds[$index]}" ]] ||
      ! bound=$(bind_script "$snapshot_dir/fixture.sh") ||
      [[ "$bound" != "$fixture_bound" ]]; then
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
