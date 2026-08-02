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

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
family_dir="$root/.github/scripts/actioncheck"
family_repo=$root
family_prefix=.github/scripts/actioncheck

if [[ "${1:-}" == --fixture ]]; then
  [[ $# -eq 1 ]] || {
    printf 'Usage: %s [--fixture]\n' "${0##*/}" >&2
    exit 2
  }
  family_dir=${CELESTIA_ACTION_FAMILY_DIR:?}
  family_repo=${CELESTIA_ACTION_FAMILY_REPO:?}
  family_prefix=${CELESTIA_ACTION_FAMILY_PREFIX:?}
elif (($# != 0)); then
  printf 'Usage: %s [--fixture]\n' "${0##*/}" >&2
  exit 2
elif [[ -n "${CELESTIA_ACTION_FAMILY_DIR:-}" ||
  -n "${CELESTIA_ACTION_FAMILY_REPO:-}" ||
  -n "${CELESTIA_ACTION_FAMILY_PREFIX:-}" ]]; then
  printf 'action family overrides require fixture mode\n' >&2
  exit 2
fi

families='remote_release_test.sh
cache_test.sh
inventory_test.sh
permissions_test.sh'

action_family_identity() {
  local family=$1
  local indexed_path
  local indexed_object
  local metadata
  local mode
  local record
  local stage
  local unexpected
  local working_object

  record=$(git -C "$family_repo" ls-files --stage -- \
    "$family_prefix/$family") || return 1
  [[ "$record" != *$'\n'* && "$record" == *$'\t'* ]] || return 1
  metadata=${record%%$'\t'*}
  indexed_path=${record#*$'\t'}
  IFS=' ' read -r mode indexed_object stage unexpected <<<"$metadata"
  [[ "$mode" == 100755 && -n "$indexed_object" && "$stage" == 0 &&
    -z "$unexpected" &&
    "$indexed_path" == "$family_prefix/$family" &&
    ! -L "$family_dir/$family" && -f "$family_dir/$family" ]] || return 1
  working_object=$(git hash-object --no-filters -- \
    "$family_dir/$family") || return 1
  [[ -n "$working_object" ]] || return 1
  printf '%s\n' "$working_object"
}

snapshot_size() {
  local size

  size=$(wc -c <"$1") || return 1
  size=${size//[[:space:]]/}
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$size"
}

snapshot_matches() {
  local path=$1
  local expected_size=$2
  local expected_identity=$3
  local identity
  local size

  [[ ! -L "$path" && -f "$path" ]] || return 1
  size=$(snapshot_size "$path") || return 1
  [[ "$size" == "$expected_size" ]] || return 1
  identity=$(git hash-object --no-filters -- "$path") || return 1
  [[ "$identity" == "$expected_identity" ]]
}

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
finish_action_driver() {
  local status=$1

  trap - EXIT
  trap '' HUP INT TERM
  if [[ -n "${driver_pid:-}" ]]; then
    kill -TERM -- "-$driver_pid" 2>/dev/null || true
    kill -KILL -- "-$driver_pid" 2>/dev/null || true
    wait "$driver_pid" 2>/dev/null || true
    driver_pid=
  fi
  if ! rm -rf -- "$action_temp_root"; then
    status=1
  fi
  exit "$status"
}

main() (
  local executed
  local family
  local family_index
  local identity
  local -a identities
  local planned
  local run_root
  local snapshot
  local snapshot_identity
  local snapshot_path
  local snapshot_size_value

  executed="$action_temp_root/executed"
  planned="$action_temp_root/planned"
  snapshot="$action_temp_root/snapshot.tar"
  family_index=0
  identities=()
  run_root=
  printf '%s\n' "$families" >"$planned"
  bash "$root/.github/scripts/testcheck.sh" action "$family_dir" "$planned" \
    "$family_repo" "$family_prefix"
  while IFS= read -r family; do
    identity=$(action_family_identity "$family") || {
      printf 'action test family is unavailable: %s\n' "$family" >&2
      return 1
    }
    identities[${#identities[@]}]=$identity
  done <<<"$families"
  git -C "$family_repo" ls-files -z | \
    tar --null -cf "$snapshot" -C "$family_repo" -T -
  snapshot_size_value=$(snapshot_size "$snapshot") || return 1
  snapshot_identity=$(git hash-object --no-filters -- "$snapshot") || return 1

  : >"$executed"
  while IFS= read -r family; do
    run_root=$(mktemp -d "$action_temp_root/run.XXXXXX")
    if ! snapshot_matches "$snapshot" "$snapshot_size_value" \
      "$snapshot_identity"; then
      printf 'action test master snapshot identity differs\n' >&2
      return 1
    fi
    tar -xf "$snapshot" -C "$run_root"
    git -C "$run_root" init -q
    git -C "$run_root" config core.autocrlf false
    git -C "$run_root" add -f .
    snapshot_path="$run_root/$family_prefix/$family"
    if [[ -L "$snapshot_path" || ! -f "$snapshot_path" ]]; then
      printf 'action test family snapshot is unavailable: %s\n' \
        "$family" >&2
      return 1
    fi
    identity=$(git hash-object --no-filters -- "$snapshot_path") || return 1
    if [[ "$identity" != "${identities[$family_index]}" ]]; then
      printf 'action test family snapshot identity differs: %s\n' \
        "$family" >&2
      return 1
    fi
    (
      cd -- "$run_root"
      bash "$snapshot_path"
    )
    rm -rf -- "$run_root"
    run_root=
    printf '%s\n' "$family" >>"$executed"
    family_index=$((family_index + 1))
  done <<<"$families"

  bash "$root/.github/scripts/testcheck.sh" action "$family_dir" "$executed" \
    "$family_repo" "$family_prefix"
)

action_temp_root=$(mktemp -d "${TMPDIR:-/tmp}/celestia-action.XXXXXX")
driver_pid=
trap 'finish_action_driver $?' EXIT
trap 'finish_action_driver 129' HUP
trap 'finish_action_driver 130' INT
trap 'finish_action_driver 143' TERM
set -m
main &
set +m
driver_pid=$!
set +e
wait "$driver_pid"
status=$?
set -e
exit "$status"
