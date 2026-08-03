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
# shellcheck source=.github/scripts/verification/fixture.sh
source "$root/.github/scripts/verification/fixture.sh"
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
  cleanup_failure=${CELESTIA_ACTION_CLEANUP_FAILURE:-0}
  [[ "$cleanup_failure" == 0 || "$cleanup_failure" == 1 ]] || {
    printf 'invalid action cleanup failure fixture\n' >&2
    exit 2
  }
  launch_checkpoint_ready=${CELESTIA_ACTION_LAUNCH_CHECKPOINT_READY:-}
  launch_checkpoint_release=${CELESTIA_ACTION_LAUNCH_CHECKPOINT_RELEASE:-}
  cancel_checkpoint_ready=${CELESTIA_ACTION_CANCEL_CHECKPOINT_READY:-}
  cancel_checkpoint_release=${CELESTIA_ACTION_CANCEL_CHECKPOINT_RELEASE:-}
  main_marker=${CELESTIA_ACTION_MAIN_MARKER:-}
  prewait_checkpoint_ready=${CELESTIA_ACTION_PREWAIT_CHECKPOINT_READY:-}
  prewait_checkpoint_release=${CELESTIA_ACTION_PREWAIT_CHECKPOINT_RELEASE:-}
  release_failure=${CELESTIA_ACTION_RELEASE_FAILURE:-0}
  [[ "$release_failure" == 0 || "$release_failure" == 1 ]] || {
    printf 'invalid action release failure fixture\n' >&2
    exit 2
  }
  release_checkpoint_ready=${CELESTIA_ACTION_RELEASE_CHECKPOINT_READY:-}
  release_checkpoint_release=${CELESTIA_ACTION_RELEASE_CHECKPOINT_RELEASE:-}
  signal_marker=${CELESTIA_ACTION_SIGNAL_MARKER:-}
  wait_checkpoint_ready=${CELESTIA_ACTION_WAIT_CHECKPOINT_READY:-}
  wait_checkpoint_release=${CELESTIA_ACTION_WAIT_CHECKPOINT_RELEASE:-}
  if [[ (-n "$launch_checkpoint_ready" &&
    -z "$launch_checkpoint_release") ||
    (-z "$launch_checkpoint_ready" &&
    -n "$launch_checkpoint_release") ||
    (-n "$cancel_checkpoint_ready" &&
    -z "$cancel_checkpoint_release") ||
    (-z "$cancel_checkpoint_ready" &&
    -n "$cancel_checkpoint_release") ||
    (-n "$prewait_checkpoint_ready" &&
    -z "$prewait_checkpoint_release") ||
    (-z "$prewait_checkpoint_ready" &&
    -n "$prewait_checkpoint_release") ||
    (-n "$release_checkpoint_ready" &&
    -z "$release_checkpoint_release") ||
    (-z "$release_checkpoint_ready" &&
    -n "$release_checkpoint_release") ||
    (-n "$wait_checkpoint_ready" && -z "$wait_checkpoint_release") ||
    (-z "$wait_checkpoint_ready" && -n "$wait_checkpoint_release") ]]; then
    printf 'incomplete action wait checkpoint fixture\n' >&2
    exit 2
  fi
elif (($# != 0)); then
  printf 'Usage: %s [--fixture]\n' "${0##*/}" >&2
  exit 2
elif [[ -n "${CELESTIA_ACTION_FAMILY_DIR:-}" ||
  -n "${CELESTIA_ACTION_FAMILY_REPO:-}" ||
  -n "${CELESTIA_ACTION_FAMILY_PREFIX:-}" ||
  -n "${CELESTIA_ACTION_CLEANUP_FAILURE:-}" ||
  -n "${CELESTIA_ACTION_CANCEL_CHECKPOINT_READY:-}" ||
  -n "${CELESTIA_ACTION_CANCEL_CHECKPOINT_RELEASE:-}" ||
  -n "${CELESTIA_ACTION_LAUNCH_CHECKPOINT_READY:-}" ||
  -n "${CELESTIA_ACTION_LAUNCH_CHECKPOINT_RELEASE:-}" ||
  -n "${CELESTIA_ACTION_MAIN_MARKER:-}" ||
  -n "${CELESTIA_ACTION_PREWAIT_CHECKPOINT_READY:-}" ||
  -n "${CELESTIA_ACTION_PREWAIT_CHECKPOINT_RELEASE:-}" ||
  -n "${CELESTIA_ACTION_RELEASE_FAILURE:-}" ||
  -n "${CELESTIA_ACTION_RELEASE_CHECKPOINT_READY:-}" ||
  -n "${CELESTIA_ACTION_RELEASE_CHECKPOINT_RELEASE:-}" ||
  -n "${CELESTIA_ACTION_SIGNAL_MARKER:-}" ||
  -n "${CELESTIA_ACTION_WAIT_CHECKPOINT_READY:-}" ||
  -n "${CELESTIA_ACTION_WAIT_CHECKPOINT_RELEASE:-}" ]]; then
  printf 'action family overrides require fixture mode\n' >&2
  exit 2
else
  cancel_checkpoint_ready=
  cancel_checkpoint_release=
  cleanup_failure=0
  launch_checkpoint_ready=
  launch_checkpoint_release=
  main_marker=
  prewait_checkpoint_ready=
  prewait_checkpoint_release=
  release_failure=0
  release_checkpoint_ready=
  release_checkpoint_release=
  signal_marker=
  wait_checkpoint_ready=
  wait_checkpoint_release=
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

snapshot_source_available() {
  local component
  local current=$family_repo
  local path=$1

  while [[ "$path" == */* ]]; do
    component=${path%%/*}
    path=${path#*/}
    [[ -n "$component" && "$component" != . && "$component" != .. ]] ||
      return 1
    current="$current/$component"
    [[ ! -L "$current" && -d "$current" ]] || return 1
  done
  [[ -n "$path" && "$path" != . && "$path" != .. ]] || return 1
  current="$current/$path"
  [[ ! -L "$current" && -f "$current" ]]
}

snapshot_source_mode_matches() {
  [[ "$1" != 100755 || -x "$2" ]]
}

snapshot_sources() {
  local indexed_object
  local indexed_path
  local inventory=$1
  local metadata
  local mode
  local record
  local source
  local stage
  local unexpected

  snapshot_modes=()
  snapshot_paths=()
  snapshot_source_paths=()
  git -C "$family_repo" ls-files --stage -z >"$inventory" || return 1
  while IFS= read -r -d '' record; do
    [[ "$record" == *$'\t'* ]] || return 1
    metadata=${record%%$'\t'*}
    indexed_path=${record#*$'\t'}
    IFS=' ' read -r mode indexed_object stage unexpected <<<"$metadata"
    case "$mode" in
    100644|100755) ;;
    *)
      printf 'action snapshot index mode is unsupported: %s\n' \
        "$indexed_path" >&2
      return 1
      ;;
    esac
    [[ "$indexed_object" =~ ^[0-9a-f]{40}$ && "$stage" == 0 &&
      -z "$unexpected" &&
      -n "$indexed_path" ]] || return 1
    git -C "$family_repo" cat-file -e "$indexed_object^{blob}" || return 1
    source="$family_repo/$indexed_path"
    if ! snapshot_source_available "$indexed_path"; then
      printf 'action snapshot source is unavailable: %s\n' \
        "$indexed_path" >&2
      return 1
    fi
    if ! snapshot_source_mode_matches "$mode" "$source"; then
      printf 'action snapshot source is not executable: %s\n' \
        "$indexed_path" >&2
      return 1
    fi
    snapshot_modes[${#snapshot_modes[@]}]=$mode
    snapshot_paths[${#snapshot_paths[@]}]=$indexed_path
    snapshot_source_paths[${#snapshot_source_paths[@]}]=$source
  done <"$inventory"
  ((${#snapshot_paths[@]} > 0))
}

snapshot_live_objects() {
  local -a chunk
  local count=${#snapshot_source_paths[@]}
  local hashes=$2
  local identity
  local index=0
  local object_store=$1
  local source

  snapshot_identities=()
  : >"$hashes" || return 1
  git init --bare -q "$object_store" || return 1
  GIT_DIR="$object_store" git config core.autocrlf false || return 1
  while ((index < count)); do
    chunk=("${snapshot_source_paths[@]:index:64}")
    GIT_DIR="$object_store" git hash-object -w --no-filters -- \
      "${chunk[@]}" >>"$hashes" || return 1
    index=$((index + ${#chunk[@]}))
  done
  while IFS= read -r identity; do
    [[ "$identity" =~ ^[0-9a-f]{40}$ ]] || return 1
    snapshot_identities[${#snapshot_identities[@]}]=$identity
  done <"$hashes"
  ((${#snapshot_identities[@]} == count)) || return 1
  index=0
  while ((index < count)); do
    source=${snapshot_source_paths[$index]}
    if ! snapshot_source_available "${snapshot_paths[$index]}"; then
      printf 'action snapshot source changed during binding: %s\n' \
        "${snapshot_paths[$index]}" >&2
      return 1
    fi
    if ! snapshot_source_mode_matches "${snapshot_modes[$index]}" \
      "$source"; then
      printf 'action snapshot source mode changed during binding: %s\n' \
        "${snapshot_paths[$index]}" >&2
      return 1
    fi
    index=$((index + 1))
  done
}

snapshot_entries_match() {
  local -a chunk
  local -a sources
  local count=${#snapshot_paths[@]}
  local hashes=$2
  local identity
  local index=0
  local path
  local root=$1

  sources=()
  : >"$hashes" || return 1
  while ((index < count)); do
    path="$root/${snapshot_paths[$index]}"
    if [[ -L "$path" || ! -f "$path" ]]; then
      printf 'action snapshot entry is unavailable: %s\n' \
        "${snapshot_paths[$index]}" >&2
      return 1
    fi
    sources[${#sources[@]}]=$path
    index=$((index + 1))
  done
  index=0
  while ((index < count)); do
    chunk=("${sources[@]:index:64}")
    git hash-object --no-filters -- "${chunk[@]}" >>"$hashes" || return 1
    index=$((index + ${#chunk[@]}))
  done
  index=0
  while IFS= read -r identity; do
    if [[ "$identity" != "${snapshot_identities[$index]:-}" ]]; then
      printf 'action snapshot entry identity differs: %s\n' \
        "${snapshot_paths[$index]:-unknown}" >&2
      return 1
    fi
    index=$((index + 1))
  done <"$hashes"
  ((index == count))
}

write_action_snapshot() {
  local index=0
  local index_file=$2
  local index_records=$3
  local object_store=$1
  local snapshot=$4
  local tree

  : >"$index_records" || return 1
  while ((index < ${#snapshot_paths[@]})); do
    printf '%s %s 0\t%s\0' "${snapshot_modes[$index]}" \
      "${snapshot_identities[$index]}" "${snapshot_paths[$index]}" \
      >>"$index_records" || return 1
    index=$((index + 1))
  done
  GIT_DIR="$object_store" GIT_INDEX_FILE="$index_file" \
    git update-index -z --index-info <"$index_records" || return 1
  tree=$(GIT_DIR="$object_store" GIT_INDEX_FILE="$index_file" \
    git write-tree) || return 1
  [[ "$tree" =~ ^[0-9a-f]{40}$ ]] || return 1
  GIT_DIR="$object_store" git archive --format=tar --output="$snapshot" \
    "$tree"
}

action_family_group_running() {
  kill -0 -- "-$active_family_pid" 2>/dev/null
}

stop_completed_action_family() {
  local attempt

  action_family_group_running || return 0
  kill -KILL -- "-$active_family_pid" 2>/dev/null || true
  attempt=0
  while action_family_group_running && ((attempt < 20)); do
    sleep 0.05
    attempt=$((attempt + 1))
  done
  if action_family_group_running &&
    ! verification_group_zombies "$active_family_pid"; then
    printf 'action test family retained a live process group\n' >&2
  fi
  return 1
}

terminate_active_action_family() {
  local attempt

  kill -KILL -- "-$active_family_pid" 2>/dev/null ||
    kill -KILL "$active_family_pid" 2>/dev/null || true
  wait "$active_family_pid" 2>/dev/null || true
  if action_family_group_running; then
    kill -KILL -- "-$active_family_pid" 2>/dev/null || true
    attempt=0
    while action_family_group_running && ((attempt < 20)); do
      sleep 0.05
      attempt=$((attempt + 1))
    done
  fi
  { ! action_family_group_running ||
    verification_group_zombies "$active_family_pid"; } &&
    [[ "$cleanup_failure" == 0 ]]
}

stop_active_action_family() {
  local signal_status=$1

  if [[ -z "$active_family_pid" && -n "$starting_family" ]]; then
    pending_family_signal=$signal_status
    return
  fi
  trap - HUP INT TERM
  if [[ -n "$active_family_pid" ]]; then
    if terminate_active_action_family; then
      active_family_pid=
    else
      printf 'action test family retained a live process group\n' >&2
      exit 1
    fi
  fi
  exit "$signal_status"
}

# shellcheck disable=SC2329 # Invoked by the registered exit trap.
finish_action_main() {
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "$active_family_pid" ]]; then
    if terminate_active_action_family; then
      active_family_pid=
    else
      printf 'action test family retained a live process group\n' >&2
      status=1
    fi
  fi
  if ! printf '%s\n' "$status" >&9; then
    status=1
  fi
  exit "$status"
}

run_action_family() {
  local cleanup_status
  local family=$3
  local path=$1
  local result
  local run_root=$2

  starting_family=1
  set -m
  (
    cd -- "$run_root"
    bash "$path" 8<&- 9>&-
  ) &
  active_family_pid=$!
  set +m
  starting_family=
  if [[ -n "$pending_family_signal" ]]; then
    result=$pending_family_signal
    pending_family_signal=
    stop_active_action_family "$result"
  fi
  set +e
  wait "$active_family_pid"
  result=$?
  stop_completed_action_family
  cleanup_status=$?
  set -e
  if ! action_family_group_running; then
    active_family_pid=
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    printf 'action test family retained descendant processes: %s\n' \
      "$family" >&2
    if [[ "$result" -eq 0 ]]; then
      return 1
    fi
  fi
  return "$result"
}

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
finish_action_driver() {
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "${driver_pid:-}" ]]; then
    if action_driver_owned; then
      kill -KILL -- "-$driver_pid" 2>/dev/null || true
    fi
    wait "$driver_pid" 2>/dev/null
    driver_pid=
    status=1
  fi
  exec 8<&- 9>&-
  if ! rm -rf -- "$action_temp_root"; then
    status=1
  fi
  exit "$status"
}

action_driver_owned() {
  [[ -n "${driver_job:-}" ]] &&
    [[ "$(jobs -p "$driver_job" 2>/dev/null)" == "$driver_pid" ]]
}

signal_owned_action_driver() {
  local signal_name=TERM

  case "$pending_driver_status" in
  129) signal_name=HUP ;;
  130) signal_name=INT ;;
  143) signal_name=TERM ;;
  esac
  action_driver_owned || return 1
  if [[ -n "$signal_marker" ]]; then
    : >"$signal_marker"
  fi
  kill -"$signal_name" -- "-$driver_pid" 2>/dev/null
}

# shellcheck disable=SC2329 # Invoked by registered signal traps.
request_action_driver_stop() {
  pending_driver_status=$1
  if [[ -n "${gate_cancel_source:-}" ]]; then
    ln "$gate_cancel_source" "$gate_decision" 2>/dev/null || true
  fi
  if [[ "${forwarding_driver_signal:-0}" -eq 0 &&
    -n "${driver_pid:-}" ]]; then
    forwarding_driver_signal=1
    if signal_owned_action_driver; then
      driver_signal_sent=1
    fi
    forwarding_driver_signal=0
  fi
}

await_cancelled_action_driver() {
  local initial_status=$1
  local driver_signalled=$2
  local gate_cancelled=$3
  local attempt=0
  local main_status
  local reaped_status
  local requested_status=$pending_driver_status
  local status_received=0
  local timed_out=0

  reaped_status=$initial_status
  if [[ "$gate_cancelled" -eq 1 ]]; then
    set +e
    wait "$driver_pid" 2>/dev/null
    reaped_status=$?
    set -e
    if action_driver_owned; then
      timed_out=1
      if action_driver_owned; then
        kill -KILL -- "-$driver_pid" 2>/dev/null || true
      fi
      set +e
      wait "$driver_pid" 2>/dev/null
      reaped_status=$?
      set -e
    fi
    if ! wait_at_action_checkpoint "$cancel_checkpoint_ready" \
      "$cancel_checkpoint_release"; then
      timed_out=1
    fi
  elif [[ "$driver_signalled" -eq 1 ]]; then
    while action_driver_owned && [[ "$attempt" -lt 1200 ]]; do
      if IFS= read -r main_status <&8; then
        status_received=1
        break
      fi
      sleep 0.01
      attempt=$((attempt + 1))
    done
    if [[ "$status_received" -eq 0 ]] && action_driver_owned; then
      timed_out=1
      if action_driver_owned; then
        kill -KILL -- "-$driver_pid" 2>/dev/null || true
      fi
    fi
    set +e
    wait "$driver_pid" 2>/dev/null
    reaped_status=$?
    set -e
  fi
  driver_pid=
  driver_job=
  if [[ "$gate_cancelled" -eq 0 && "$reaped_status" -eq 127 ]]; then
    reaped_status=$initial_status
  fi
  if [[ "$status_received" -eq 0 ]] && IFS= read -r main_status <&8; then
    status_received=1
  fi
  if [[ "$status_received" -eq 0 ]] ||
    IFS= read -r _ <&8 ||
    [[ ! "$main_status" =~ ^(0|[1-9][0-9]{0,2})$ ]] ||
    ((main_status > 255)); then
    main_status=1
  fi
  if [[ "$timed_out" -eq 1 ]]; then
    printf 'action driver cancellation cleanup failed\n' >&2
    return 1
  fi
  if [[ "$gate_cancelled" -eq 1 ]]; then
    if [[ "$requested_status" != 129 && "$requested_status" != 130 &&
      "$requested_status" != 143 ]] ||
      [[ "$reaped_status" -ne 0 &&
      "$reaped_status" -ne "$requested_status" ]] ||
      [[ "$main_status" -ne 0 && "$main_status" -ne "$requested_status" ]]; then
      printf 'action driver cancellation cleanup failed\n' >&2
      return 1
    fi
    return "$requested_status"
  fi
  if [[ "$driver_signalled" -eq 0 ]]; then
    return "$main_status"
  fi
  if [[ "$main_status" -ne 0 && "$main_status" -ne "$requested_status" ]]; then
    printf 'action driver cancellation cleanup failed\n' >&2
    return 1
  fi
  return "$requested_status"
}

wait_at_action_checkpoint() {
  local ready=$1
  local release=$2
  local attempt=0

  [[ -n "$ready" ]] || return 0
  : >"$ready"
  while [[ ! -e "$release" && attempt -lt 500 ]]; do
    sleep 0.01
    attempt=$((attempt + 1))
  done
  [[ -e "$release" ]]
}

await_action_release() {
  local attempt=0
  local decision

  while [[ ! -e "$gate_decision" && attempt -lt 500 ]]; do
    sleep 0.01
    attempt=$((attempt + 1))
  done
  if [[ ! -f "$gate_decision" ]] ||
    ! IFS= read -r decision <"$gate_decision"; then
    return 1
  fi
  rm -f -- "$gate_cancel_source" "$gate_release_source" "$gate_decision" ||
    return 1
  case "$decision" in
  release) return 0 ;;
  cancel) return 2 ;;
  *) return 1 ;;
  esac
}

main() (
  local active_family_pid
  local executed
  local family
  local family_index
  local gate_status
  local identity
  local -a identities
  local planned
  local pending_family_signal
  local run_root
  local snapshot
  local snapshot_entry_hashes
  local snapshot_hashes
  local snapshot_identity
  local snapshot_index
  local snapshot_inventory
  local snapshot_index_records
  local snapshot_object_store
  local snapshot_path
  local snapshot_size_value
  local snapshot_validation
  local -a snapshot_identities
  local -a snapshot_modes
  local -a snapshot_paths
  local -a snapshot_source_paths
  local starting_family

  active_family_pid=
  executed="$action_temp_root/executed"
  planned="$action_temp_root/planned"
  snapshot="$action_temp_root/snapshot.tar"
  snapshot_entry_hashes="$action_temp_root/snapshot-entry-hashes"
  snapshot_hashes="$action_temp_root/snapshot-hashes"
  snapshot_index="$action_temp_root/snapshot-index-file"
  snapshot_inventory="$action_temp_root/snapshot-index"
  snapshot_index_records="$action_temp_root/snapshot-index-records"
  snapshot_object_store="$action_temp_root/snapshot-objects"
  snapshot_validation="$action_temp_root/snapshot-validation"
  family_index=0
  identities=()
  pending_family_signal=
  run_root=
  starting_family=
  trap 'finish_action_main $?' EXIT
  set +e
  await_action_release
  gate_status=$?
  set -e
  case "$gate_status" in
  0) ;;
  2) return 0 ;;
  *) return 1 ;;
  esac
  if [[ -n "$main_marker" ]]; then
    : >"$main_marker"
  fi
  trap 'stop_active_action_family 129' HUP
  trap 'stop_active_action_family 130' INT
  trap 'stop_active_action_family 143' TERM
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
  snapshot_sources "$snapshot_inventory" || return 1
  snapshot_live_objects "$snapshot_object_store" "$snapshot_hashes" ||
    return 1
  write_action_snapshot "$snapshot_object_store" "$snapshot_index" \
    "$snapshot_index_records" "$snapshot" || return 1
  snapshot_size_value=$(snapshot_size "$snapshot") || return 1
  snapshot_identity=$(git hash-object --no-filters -- "$snapshot") || return 1
  mkdir -- "$snapshot_validation" || return 1
  tar -xf "$snapshot" -C "$snapshot_validation" || return 1
  snapshot_entries_match "$snapshot_validation" "$snapshot_entry_hashes" ||
    return 1
  rm -rf -- "$snapshot_validation" || return 1

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
    run_action_family "$snapshot_path" "$run_root" "$family"
    rm -rf -- "$run_root"
    run_root=
    printf '%s\n' "$family" >>"$executed"
    family_index=$((family_index + 1))
  done <<<"$families"

  bash "$root/.github/scripts/testcheck.sh" action "$family_dir" "$executed" \
    "$family_repo" "$family_prefix"
)

action_temp_root=$(mktemp -d "${TMPDIR:-/tmp}/celestia-action.XXXXXX")
gate_cancel_source="$action_temp_root/start-cancel"
gate_decision="$action_temp_root/start-decision"
gate_release_source="$action_temp_root/start-release"
printf 'cancel\n' >"$gate_cancel_source"
printf 'release\n' >"$gate_release_source"
: >"$action_temp_root/main-status"
exec 8<"$action_temp_root/main-status"
exec 9>"$action_temp_root/main-status"
rm -- "$action_temp_root/main-status"
driver_pid=
driver_job=
driver_signal_sent=0
forwarding_driver_signal=0
pending_driver_status=
trap 'finish_action_driver $?' EXIT
trap 'request_action_driver_stop 129' HUP
trap 'request_action_driver_stop 130' INT
trap 'request_action_driver_stop 143' TERM
if ! wait_at_action_checkpoint "$launch_checkpoint_ready" \
  "$launch_checkpoint_release"; then
  exit 1
fi
if [[ -n "$pending_driver_status" ]]; then
  exec 9>&-
  exit "$pending_driver_status"
fi
set -m
main 8<&- &
set +m
driver_pid=$!
driver_job=%1
exec 9>&-
gate_cancelled=0
release_selected=0
if ! wait_at_action_checkpoint "$release_checkpoint_ready" \
  "$release_checkpoint_release"; then
  request_action_driver_stop 1
fi
if [[ -z "$pending_driver_status" ]]; then
  if [[ "$release_failure" -eq 1 ]]; then
    rm -- "$gate_release_source"
  fi
  if ln "$gate_release_source" "$gate_decision" 2>/dev/null; then
    release_selected=1
  elif [[ ! -e "$gate_decision" ]]; then
    request_action_driver_stop 1
  fi
fi
if [[ "$release_selected" -eq 0 ]]; then
  gate_cancelled=1
fi
if ! wait_at_action_checkpoint "$prewait_checkpoint_ready" \
  "$prewait_checkpoint_release"; then
  request_action_driver_stop 1
fi
status=0
if [[ -z "$pending_driver_status" ]]; then
  set +e
  wait "$driver_pid"
  status=$?
  set -e
  if ! wait_at_action_checkpoint "$wait_checkpoint_ready" \
    "$wait_checkpoint_release"; then
    status=1
  fi
fi
if [[ -n "$pending_driver_status" ]]; then
  trap '' HUP INT TERM
  driver_signalled=$driver_signal_sent
  if [[ "$gate_cancelled" -eq 0 && "$driver_signalled" -eq 0 ]] &&
    signal_owned_action_driver; then
    driver_signalled=1
  fi
  set +e
  await_cancelled_action_driver "$status" "$driver_signalled" \
    "$gate_cancelled"
  status=$?
  set -e
else
  driver_pid=
  driver_job=
fi
exit "$status"
