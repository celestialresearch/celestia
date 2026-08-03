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
family_dir="$root/.github/scripts/verification"
family_repo=$root
family_prefix=.github/scripts/verification
families=(
  lint_test.sh
  action_test.sh
  devcheck_config_test.sh
  rust_config_test.sh
  rust_integration_test.sh
  rust_artefact_test.sh
  coverage_test.sh
  source_policy_test.sh
  licence_test.sh
  release_artefact_test.sh
)

fixture_mode=${1:-}
driver_status_failure=
driver_spawn_checkpoint=
driver_completion_checkpoint=
driver_wait_checkpoint=
family_wait_checkpoint=
family_deadline_checkpoint=
family_timeout_seconds=600
deadline_marker_failure=
deadline_notify_failure=
case "$fixture_mode" in
"") ;;
--fixture)
  family_dir=${CELESTIA_VERIFICATION_FAMILY_DIR:?}
  family_repo=${CELESTIA_VERIFICATION_FAMILY_REPO:?}
  family_prefix=${CELESTIA_VERIFICATION_FAMILY_PREFIX:?}
  driver_status_failure=${CELESTIA_VERIFICATION_DRIVER_STATUS_FAILURE:-}
  driver_spawn_checkpoint=${CELESTIA_VERIFICATION_DRIVER_SPAWN_CHECKPOINT:-}
  driver_completion_checkpoint=${CELESTIA_VERIFICATION_DRIVER_COMPLETION_CHECKPOINT:-}
  driver_wait_checkpoint=${CELESTIA_VERIFICATION_DRIVER_WAIT_CHECKPOINT:-}
  family_wait_checkpoint=${CELESTIA_VERIFICATION_FAMILY_WAIT_CHECKPOINT:-}
  family_deadline_checkpoint=${CELESTIA_VERIFICATION_FAMILY_DEADLINE_CHECKPOINT:-}
  family_timeout_seconds=${CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS:-600}
  deadline_marker_failure=${CELESTIA_VERIFICATION_DEADLINE_MARKER_FAILURE:-}
  deadline_notify_failure=${CELESTIA_VERIFICATION_DEADLINE_NOTIFY_FAILURE:-}
  [[ -z "$driver_status_failure" || "$driver_status_failure" == 1 ||
    "$driver_status_failure" == missing ||
    "$driver_status_failure" == leading-zero ||
    "$driver_status_failure" == out-of-range ||
    "$driver_status_failure" == extra-line ]] || {
    printf 'verification driver status fixture is invalid\n' >&2
    exit 2
  }
  for checkpoint in "$driver_spawn_checkpoint" "$driver_completion_checkpoint" \
    "$driver_wait_checkpoint" "$family_wait_checkpoint" \
    "$family_deadline_checkpoint"; do
    if [[ -n "$checkpoint" ]] &&
      [[ -L "$checkpoint" || ! -f "$checkpoint" || ! -x "$checkpoint" ]]; then
      printf 'verification lifecycle checkpoint is unavailable\n' >&2
      exit 2
    fi
  done
  if [[ ! "$family_timeout_seconds" =~ ^[1-9][0-9]*$ ]] ||
    [[ "${#family_timeout_seconds}" -gt 4 ]] ||
    ((family_timeout_seconds > 3600)); then
    printf 'verification family timeout fixture is invalid\n' >&2
    exit 2
  fi
  if [[ -n "$deadline_marker_failure" &&
    "$deadline_marker_failure" != 1 ]] ||
    [[ -n "$deadline_notify_failure" &&
      "$deadline_notify_failure" != once ]]; then
    printf 'verification family deadline failure fixture is invalid\n' >&2
    exit 2
  fi
  ;;
*)
  printf 'Usage: verification_test.sh [--fixture]\n' >&2
  exit 2
  ;;
esac
if [[ "$fixture_mode" != --fixture ]] &&
  [[ -n "${CELESTIA_VERIFICATION_FAMILY_DIR+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_REPO+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_PREFIX+x}" ||
    -n "${CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT+x}" ||
    -n "${CELESTIA_VERIFICATION_DRIVER_STATUS_FAILURE+x}" ||
    -n "${CELESTIA_VERIFICATION_DRIVER_SPAWN_CHECKPOINT+x}" ||
    -n "${CELESTIA_VERIFICATION_DRIVER_COMPLETION_CHECKPOINT+x}" ||
    -n "${CELESTIA_VERIFICATION_DRIVER_WAIT_CHECKPOINT+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_WAIT_CHECKPOINT+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_DEADLINE_CHECKPOINT+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS+x}" ||
    -n "${CELESTIA_VERIFICATION_DEADLINE_MARKER_FAILURE+x}" ||
    -n "${CELESTIA_VERIFICATION_DEADLINE_NOTIFY_FAILURE+x}" ]]; then
  printf 'verification family overrides require fixture mode\n' >&2
  exit 2
fi

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
terminate_family() {
  local attempt
  local pid=$1

  kill -KILL -- "-$pid" 2>/dev/null || true
  attempt=0
  while kill -0 -- "-$pid" 2>/dev/null && ((attempt < 40)); do
    sleep 0.05
    attempt=$((attempt + 1))
  done
  ! kill -0 -- "-$pid" 2>/dev/null || verification_group_zombies "$pid"
}

path_is_within() {
  local candidate=$1
  local parent
  local root_path=$2

  while :; do
    [[ "$candidate" -ef "$root_path" ]] && return 0
    parent=$(cd -- "$candidate/.." && pwd -P) || return 1
    [[ "$parent" -ef "$candidate" ]] && return 1
    candidate=$parent
  done
}

# shellcheck disable=SC2329 # Invoked through registered exit handlers.
job_owned() {
  local job=$1
  local pid=$2
  local record=$3
  local job_pid=

  [[ -n "$job" ]] || return 1
  jobs -r -p >"$record" 2>/dev/null || true
  jobs -s -p >>"$record" 2>/dev/null || true
  while IFS= read -r job_pid; do
    [[ "$job_pid" == "$pid" ]] && break
    job_pid=
  done <"$record"
  rm -f -- "$record"
  [[ "$job_pid" == "$pid" ]]
}

driver_job_owned() {
  local pid=$1

  job_owned "$driver_job" "$pid" "$driver_work/driver-job"
}

# shellcheck disable=SC2329 # Invoked through registered exit handlers.
terminate_driver() {
  local attempt=0
  local cleanup_status=0
  local pid=$1

  if driver_job_owned "$pid"; then
    if [[ -n "$driver_signal_pid" ]]; then
      kill -TERM "$driver_signal_pid" 2>/dev/null || true
    else
      kill -TERM -- "-$pid" 2>/dev/null || true
    fi
    while driver_job_owned "$pid" && ((attempt < 60)); do
      sleep 0.05
      attempt=$((attempt + 1))
    done
    if driver_job_owned "$pid"; then
      kill -KILL -- "-$pid" 2>/dev/null || true
    fi
  fi
  set +e
  wait "$pid" 2>/dev/null
  driver_child_status=$?
  set -e
  terminate_family "$pid" || cleanup_status=1
  if ! read_driver_status; then
    cleanup_status=1
  fi
  return "$cleanup_status"
}

# shellcheck disable=SC2329 # Invoked by terminate_driver during exit handling.
read_driver_status() {
  local extra_status
  local extra=
  local reported_status=

  if ! IFS= read -r reported_status <&9; then
    exec 9<&-
    printf 'verification driver status is invalid\n' >&2
    return 1
  fi
  set +e
  IFS= read -r extra <&9
  extra_status=$?
  set -e
  exec 9<&-
  if [[ ! "$reported_status" =~ ^(0|[1-9][0-9]*)$ ]] ||
    [[ "$extra_status" -eq 0 || -n "$extra" ]] ||
    [[ "${#reported_status}" -gt 3 ]] ||
    ((reported_status > 255)); then
    printf 'verification driver status is invalid\n' >&2
    return 1
  fi
  driver_child_status=$reported_status
}

read_driver_identity() {
  local attempt=0
  local reported_pid=

  while ! IFS= read -r reported_pid <&9; do
    if ((attempt >= 200)); then
      printf 'verification driver identity is invalid\n' >&2
      return 1
    fi
    sleep 0.05 || true
    attempt=$((attempt + 1))
  done
  if [[ ! "$reported_pid" =~ ^[1-9][0-9]*$ ]] ||
    [[ "${#reported_pid}" -gt 10 ]]; then
    printf 'verification driver identity is invalid\n' >&2
    return 1
  fi
  driver_signal_pid=$reported_pid
}

family_group_running() {
  kill -0 -- "-$active_family_pid" 2>/dev/null
}

family_job_owned() {
  job_owned "$active_family_job" "$active_family_pid" "$family_job_record"
}

stop_owned_family() {
  local pid=$active_family_pid

  kill -KILL -- "-$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  terminate_family "$pid"
}

start_family_deadline() {
  local controller_pid=$family_controller_pid

  rm -f -- "$family_deadline_marker"
  (
    local attempt=0
    local status=0

    set +e
    sleep "$family_timeout_seconds"
    # Publishing the marker commits timeout before notifying the controller.
    if [[ "$deadline_marker_failure" == 1 ]] ||
      ! printf '%s\n' "$controller_pid" >"$family_deadline_marker"; then
      status=1
    fi
    if [[ -n "$family_deadline_checkpoint" ]]; then
      CELESTIA_VERIFICATION_FAMILY_CONTROLLER_PID=$controller_pid \
        "$family_deadline_checkpoint" || status=1
    fi
    while :; do
      if [[ "$deadline_notify_failure" == once && "$attempt" -eq 0 ]]; then
        status=1
      elif kill -ALRM "$controller_pid" 2>/dev/null; then
        break
      fi
      attempt=$((attempt + 1))
      ((attempt < 40)) || exit 1
      sleep 0.05
    done
    exit "$status"
  ) &
  active_family_deadline_pid=$!
}

stop_family_deadline() {
  local deadline_pid=$active_family_deadline_pid

  [[ -n "$deadline_pid" ]] || return 0
  kill -KILL -- "-$deadline_pid" 2>/dev/null || true
  wait "$deadline_pid" 2>/dev/null || true
  active_family_deadline_pid=
  ! kill -0 "$deadline_pid" 2>/dev/null
}

join_family_deadline() {
  local attempt=0
  local deadline_pid=$active_family_deadline_pid
  local status

  while :; do
    if wait "$deadline_pid" 2>/dev/null; then
      status=0
    else
      status=$?
    fi
    if [[ "$status" -eq 0 || "$status" -eq 1 ]]; then
      return "$status"
    fi
    ((status > 128)) || return 1
    attempt=$((attempt + 1))
    ((attempt < 4)) || return 1
  done
}

settle_family_deadline() {
  local deadline_status

  [[ -n "$active_family_deadline_pid" ]] || return 0
  if [[ -n "$family_event_status" && "$family_event_status" -ne 124 ]]; then
    stop_family_deadline || return 1
    rm -f -- "$family_deadline_marker"
    return 0
  fi
  if [[ "$family_timeout_pending" -eq 1 ||
    -f "$family_deadline_marker" ]]; then
    if join_family_deadline; then
      deadline_status=0
    else
      deadline_status=$?
    fi
    active_family_deadline_pid=
    if [[ "$deadline_status" -ne 0 ||
      ! -f "$family_deadline_marker" ]]; then
      rm -f -- "$family_deadline_marker"
      return 125
    fi
    rm -f -- "$family_deadline_marker"
    return 124
  fi
  stop_family_deadline || return 1
  if [[ -f "$family_deadline_marker" ]]; then
    rm -f -- "$family_deadline_marker"
    return 124
  fi
}

stop_timed_out_family() {
  local pid=$active_family_pid

  kill -TERM -- "-$pid" 2>/dev/null || true
  sleep 1
  kill -KILL -- "-$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  terminate_family "$pid"
}

stop_completed_family_group() {
  family_group_running || return 0
  if ! stop_owned_family; then
    printf 'verification family retained a live process group\n' >&2
    return 2
  fi
  return 1
}

reconcile_active_family() {
  local completed=${1:-0}
  local cleanup_status

  if [[ "$completed" -eq 0 ]] && family_job_owned; then
    if stop_owned_family; then
      return 0
    fi
    return 2
  fi
  if stop_completed_family_group; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  return "$cleanup_status"
}

# shellcheck disable=SC2329 # Invoked through the registered exit handler.
finish_main() {
  local status=$?
  local cleanup_status
  local deadline_status

  trap - EXIT HUP INT TERM
  set +e
  settle_family_deadline
  deadline_status=$?
  family_timeout_pending=0
  set -e
  if [[ "$deadline_status" -eq 124 ]]; then
    status=124
  elif [[ "$deadline_status" -eq 125 ]]; then
    printf 'verification family deadline mechanism failed\n' >&2
    status=1
  elif [[ "$deadline_status" -ne 0 ]]; then
    printf 'verification family deadline cleanup remained incomplete\n' >&2
    status=1
  fi
  if [[ -n "$active_family_pid" ]]; then
    set +e
    reconcile_active_family
    cleanup_status=$?
    set -e
    if [[ "$cleanup_status" -eq 0 ]]; then
      active_family_pid=
      active_family_job=
    elif [[ "$cleanup_status" -eq 1 ]]; then
      printf 'verification family left descendant processes\n' >&2
      active_family_pid=
      active_family_job=
      if [[ "$status" -eq 0 ]]; then
        status=1
      fi
    else
      printf 'verification family cleanup remained incomplete\n' >&2
      status=1
    fi
  fi
  if [[ "$status" -eq 0 && -n "$pending_family_signal" ]]; then
    status=$pending_family_signal
  fi
  if [[ "$driver_status_failure" == 1 ]]; then
    status=1
  fi
  if [[ "$driver_status_failure" == missing ]]; then
    :
  elif [[ "$driver_status_failure" == leading-zero ]]; then
    printf '01\n' >&8 || status=1
  elif [[ "$driver_status_failure" == out-of-range ]]; then
    printf '256\n' >&8 || status=1
  elif [[ "$driver_status_failure" == extra-line ]]; then
    printf '1\n2\n' >&8 || status=1
  elif ! printf '%d\n' "$status" >&8; then
    status=1
  fi
  exec 8>&-
  exit "$status"
}

# shellcheck disable=SC2329 # Invoked by registered signal traps.
record_family_signal() {
  if [[ -z "$family_event_status" ]]; then
    if [[ -f "$family_deadline_marker" ]]; then
      family_event_status=124
      family_timeout_pending=1
    else
      family_event_status=$1
      pending_family_signal=$1
    fi
  fi
  if [[ "$family_event_status" -eq "$1" && -n "$active_family_pid" ]] &&
    job_owned "$active_family_job" "$active_family_pid" \
      "$family_signal_job_record"; then
    family_signal_forwarded=1
    kill -"$2" -- "-$active_family_pid" 2>/dev/null || true
  fi
  return 0
}

# shellcheck disable=SC2329 # Invoked by the registered deadline trap.
record_family_timeout() {
  family_timeout_pending=1
  if [[ -z "$family_event_status" && -f "$family_deadline_marker" ]]; then
    family_event_status=124
  fi
  return 0
}

# shellcheck disable=SC2329 # Invoked by registered signal traps.
record_driver_signal() {
  pending_driver_signal=$1
  if [[ -n "$driver_pid" && -n "$driver_signal_pid" ]] &&
    job_owned "$driver_job" "$driver_pid" \
      "$driver_work/driver-signal-job"; then
    driver_signal_forwarded=1
    kill -"$2" "$driver_signal_pid" 2>/dev/null || true
  fi
  return 0
}

run_family() {
  local cleanup_status
  local deadline_status
  local family=$2
  local path=$1
  local result
  local signal_status=
  local deadline_failed=0
  local timed_out=0
  local wait_completed=0

  family_signal_forwarded=
  family_timeout_pending=0
  family_event_status=
  if [[ -n "$pending_family_signal" ]]; then
    signal_status=$pending_family_signal
    pending_family_signal=
    return "$signal_status"
  fi
  set -m
  CELESTIA_VERIFICATION_ROOT="$root" "$path" 8>&- 9>&- &
  active_family_pid=$!
  active_family_job=$active_family_pid
  start_family_deadline
  if [[ -n "$pending_family_signal" ]]; then
    signal_status=$pending_family_signal
    pending_family_signal=
    if ! stop_family_deadline; then
      printf 'verification family deadline cleanup remained incomplete: %s\n' \
        "$family" >&2
      return 1
    fi
    if reconcile_active_family; then
      cleanup_status=0
    else
      cleanup_status=$?
    fi
    if [[ "$cleanup_status" -eq 1 ]]; then
      printf 'verification family left descendant processes: %s\n' \
        "$family" >&2
      active_family_pid=
      active_family_job=
      return 1
    elif [[ "$cleanup_status" -eq 2 ]]; then
      printf 'verification family left descendant processes: %s\n' \
        "$family" >&2
      return 1
    fi
    active_family_pid=
    active_family_job=
    return "$signal_status"
  fi
  if [[ -n "$family_wait_checkpoint" ]]; then
    CELESTIA_VERIFICATION_WAITING_FAMILY_PID=$active_family_pid \
      CELESTIA_VERIFICATION_FAMILY_CONTROLLER_PID=$family_controller_pid \
      "$family_wait_checkpoint"
  fi
  set +e
  wait "$active_family_pid"
  result=$?
  if [[ "$family_timeout_pending" -eq 1 ]]; then
    if ! stop_timed_out_family; then
      printf 'verification timed-out family cleanup remained incomplete: %s\n' \
        "$family" >&2
      return 1
    fi
    wait_completed=1
  fi
  settle_family_deadline
  deadline_status=$?
  family_timeout_pending=0
  set -e
  if [[ "$deadline_status" -ne 0 && "$deadline_status" -ne 124 ]]; then
    deadline_failed=1
  fi
  if [[ "$deadline_status" -eq 124 ]]; then
    timed_out=1
  fi
  set +m
  if [[ -z "$pending_family_signal" ]] || ! family_job_owned; then
    wait_completed=1
  fi
  signal_status=$pending_family_signal
  pending_family_signal=
  if reconcile_active_family "$wait_completed"; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  if [[ "$cleanup_status" -eq 0 ]] && family_group_running; then
    cleanup_status=2
  fi
  if [[ "$cleanup_status" -ne 2 ]]; then
    active_family_pid=
    active_family_job=
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    printf 'verification family left descendant processes: %s\n' \
      "$family" >&2
    return 1
  fi
  if [[ "$timed_out" -eq 1 ]]; then
    printf 'verification family timed out: %s\n' "$family" >&2
    return 124
  fi
  if [[ "$deadline_failed" -eq 1 ]]; then
    printf 'verification family deadline mechanism failed: %s\n' \
      "$family" >&2
    return 1
  fi
  if [[ -n "$signal_status" ]] &&
    [[ "$family_signal_forwarded" == 1 || "$wait_completed" -eq 0 ]]; then
    return "$signal_status"
  fi
  return "$result"
}

# shellcheck disable=SC2329 # Invoked through the registered exit handler.
cleanup_driver() {
  local status=0

  if [[ -n "${snapshot_root:-}" && -e "$snapshot_root" ]]; then
    chmod -R u+w -- "$snapshot_root" || status=1
    rm -rf -- "$snapshot_root" || status=1
  fi
  if [[ -n "${driver_work:-}" && -e "$driver_work" ]]; then
    rm -rf -- "$driver_work" || status=1
  fi
  return "$status"
}

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
finish_driver() {
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "${driver_pid:-}" ]]; then
    if ! terminate_driver "$driver_pid"; then
      printf 'verification driver cleanup remained incomplete\n' >&2
      status=1
    elif [[ "$status" == 129 || "$status" == 130 || "$status" == 143 ]] &&
      [[ "$driver_child_status" -ne 0 &&
        "$driver_child_status" -ne "$status" ]]; then
      printf 'verification driver inner cleanup failed\n' >&2
      status=1
    fi
    driver_pid=
    driver_signal_pid=
  fi
  if ! cleanup_driver; then
    status=1
  fi
  exit "$status"
}

snapshot_family_tree() {
  local destination=$1
  local manifest=$2
  local bindings=$3
  local binding
  local binding_digest
  local binding_index=0
  local binding_size
  local copied_digest
  local copied_size
  local metadata
  local mode
  local path
  local record
  local relative
  local source
  local stage
  local target

  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    path=${record#*$'\t'}
    mode=${metadata%% *}
    metadata=${metadata#* }
    stage=${metadata##* }
    case "$path" in
    "$family_prefix"/*) relative=${path#"$family_prefix/"} ;;
    *)
      printf 'verification snapshot escaped its prefix\n' >&2
      return 1
      ;;
    esac
    case "$relative" in
    "" | /* | *$'\n'* | *$'\r'* | ../* | */../* | */..)
      printf 'verification snapshot has an unsupported path\n' >&2
      return 1
      ;;
    esac
    if [[ "$stage" != 0 ||
      ("$mode" != 100644 && "$mode" != 100755) ]]; then
      printf 'verification snapshot has an unsupported entry: %s\n' \
        "$relative" >&2
      return 1
    fi
    source="$family_repo/$path"
    target="$destination/$relative"
    binding="$bindings/$binding_index/object"
    binding_index=$((binding_index + 1))
    if ! snapshot_source_available "$family_repo" "$path"; then
      printf 'verification snapshot source is unavailable: %s\n' \
        "$relative" >&2
      return 1
    fi
    if [[ "$mode" == 100755 && ! -x "$source" ]]; then
      printf 'verification snapshot source mode differs: %s\n' \
        "$relative" >&2
      return 1
    fi
    mkdir -p -- "${target%/*}"
    mkdir -- "${binding%/*}"
    if ! cat -- "$source" >"$binding" ||
      ! snapshot_source_available "$family_repo" "$path" ||
      ! cmp -s -- "$source" "$binding"; then
      printf 'verification snapshot source changed: %s\n' "$relative" >&2
      return 1
    fi
    binding_size=$(wc -c <"$binding")
    binding_digest=$(git hash-object --no-filters -- "$binding")
    chmod 400 -- "$binding"
    chmod 500 -- "${binding%/*}"
    if [[ -n "${CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT:-}" ]]; then
      if [[ -L "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT" ||
        ! -f "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT" ||
        ! -x "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT" ]]; then
        printf 'verification snapshot checkpoint is unavailable\n' >&2
        return 1
      fi
      CELESTIA_VERIFICATION_SNAPSHOT_PATH=$relative \
        "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT"
    fi
    copied_size=$(wc -c <"$binding")
    if ! snapshot_source_available "$family_repo" "$path" ||
      [[ "$copied_size" != "$binding_size" ]] ||
      ! cmp -s -- "$source" "$binding" ||
      ! cp -- "$binding" "$target"; then
      printf 'verification snapshot source changed: %s\n' "$relative" >&2
      return 1
    fi
    copied_size=$(wc -c <"$target")
    copied_digest=$(git hash-object --no-filters -- "$target")
    if [[ -L "$target" || ! -f "$target" ]] ||
      [[ "$copied_size" != "$binding_size" ||
        "$copied_digest" != "$binding_digest" ]] ||
      ! cmp -s -- "$binding" "$target"; then
      printf 'verification snapshot copy differs: %s\n' "$relative" >&2
      return 1
    fi
    if [[ "$mode" == 100755 ]]; then
      chmod 500 -- "$target"
    else
      chmod 400 -- "$target"
    fi
  done <"$manifest"
  find "$destination" -type d -exec chmod 500 {} +
}

snapshot_source_available() {
  local component
  local current=$1
  local path=$2
  local remainder=$2
  local visited=0

  [[ ! -L "$current" && -d "$current" ]] || return 1
  [[ -n "$path" && "${#path}" -le 4096 ]] || return 1
  while [[ "$remainder" == */* ]]; do
    component=${remainder%%/*}
    remainder=${remainder#*/}
    [[ -n "$component" && "$component" != . && "$component" != .. ]] ||
      return 1
    current="$current/$component"
    [[ ! -L "$current" && -d "$current" ]] || return 1
    visited=$((visited + 1))
    ((visited <= 128)) || return 1
  done
  [[ -n "$remainder" && "$remainder" != . && "$remainder" != .. ]] ||
    return 1
  current="$current/$remainder"
  [[ ! -L "$current" && -f "$current" ]]
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

main() (
  local active_family_deadline_pid=
  local active_family_job=
  local active_family_pid=
  local work=$1
  local snapshot=$2
  local declared
  local bindings
  local executed
  local family
  local family_job_record
  local family_controller_pid=
  local family_deadline_marker
  local family_signal_job_record
  local family_signal_forwarded=
  local family_event_status=
  local family_timeout_pending=0
  local manifest
  local master
  local master_identity
  local master_size
  local path
  local pending_family_signal=
  local source
  local status

  trap finish_main EXIT
  trap 'record_family_signal 129 HUP' HUP
  trap 'record_family_signal 130 INT' INT
  trap 'record_family_signal 143 TERM' TERM
  trap record_family_timeout ALRM

  if ! bash --noprofile --norc -c 'printf "%s\n" "$PPID"' \
    >"$work/controller-pid" ||
    ! IFS= read -r family_controller_pid <"$work/controller-pid" ||
    [[ ! "$family_controller_pid" =~ ^[1-9][0-9]*$ ]] ||
    [[ "${#family_controller_pid}" -gt 10 ]]; then
    printf 'verification driver identity is invalid\n' >&2
    return 1
  fi
  rm -- "$work/controller-pid"
  printf '%s\n' "$family_controller_pid" >&8

  declared="$work/declared"
  bindings="$work/bindings"
  executed="$work/executed"
  family_job_record="$work/family-job"
  family_deadline_marker="$work/family-deadline"
  family_signal_job_record="$work/family-signal-job"
  manifest="$work/manifest"
  master="$work/source.tar"
  source="$work/source"
  mkdir -- "$bindings" "$source"
  printf '%s\n' "${families[@]}" >"$declared"
  bash "$root/.github/scripts/testcheck.sh" verification "$family_dir" \
    "$declared" "$family_repo" "$family_prefix"
  git -C "$family_repo" ls-files --stage -z -- "$family_prefix" >"$manifest"
  snapshot_family_tree "$source" "$manifest" "$bindings"
  tar -cf "$master" -C "$source" .
  master_size=$(snapshot_size "$master") || return 1
  master_identity=$(git hash-object --no-filters -- "$master") || return 1
  chmod 400 -- "$master"
  chmod -R u+w -- "$source" "$bindings"
  rm -rf -- "$source" "$bindings"
  for family in "${families[@]}"; do
    chmod -R u+w -- "$snapshot"
    rm -rf -- "$snapshot"
    mkdir -- "$snapshot"
    if ! snapshot_matches "$master" "$master_size" "$master_identity"; then
      printf 'verification master snapshot identity differs\n' >&2
      return 1
    fi
    tar -xf "$master" -C "$snapshot"
    path="$snapshot/$family"
    if [[ -L "$path" || ! -f "$path" || ! -x "$path" ]]; then
      printf 'verification family is unavailable: %s\n' "$family" >&2
      return 1
    fi
    set +e
    run_family "$path" "$family"
    status=$?
    set -e
    if [[ "$status" -ne 0 ]]; then
      return "$status"
    fi
    printf '%s\n' "$family" >>"$executed"
  done
  if ! cmp -s "$declared" "$executed"; then
    printf 'verification families lacked ordered execution\n' >&2
    return 1
  fi
)

driver_pid=
driver_job=
driver_child_status=0
driver_work=
driver_status=
driver_signal_forwarded=
driver_signal_pid=
pending_driver_signal=
snapshot_root=
spawn_checkpoint_status=0
driver_temp_root=
trap 'finish_driver $?' EXIT
trap 'record_driver_signal 129 HUP' HUP
trap 'record_driver_signal 130 INT' INT
trap 'record_driver_signal 143 TERM' TERM
driver_temp_root=$(cd -- "${TMPDIR:-/tmp}" && pwd -P) || {
  printf 'verification temporary root is unavailable\n' >&2
  exit 1
}
if path_is_within "$driver_temp_root" "$root"; then
  printf 'verification temporary root is inside the repository\n' >&2
  exit 1
fi
driver_work=$(mktemp -d \
  "$driver_temp_root/celestia-verification-driver.XXXXXX")
snapshot_root="$driver_work/snapshot"
mkdir -- "$snapshot_root"
driver_status="$driver_work/status"
: >"$driver_status"
exec 8>"$driver_status"
exec 9<"$driver_status"
rm -- "$driver_status"
if [[ -n "$pending_driver_signal" ]]; then
  exit "$pending_driver_signal"
fi
set -m
main "$driver_work" "$snapshot_root" "$@" 9>&- &
spawned_driver_pid=$!
driver_job=%+
driver_pid=$spawned_driver_pid
if ! read_driver_identity; then
  exit 1
fi
if [[ -n "$driver_spawn_checkpoint" ]]; then
  if ! CELESTIA_VERIFICATION_SPAWNED_DRIVER_PID=$spawned_driver_pid \
    "$driver_spawn_checkpoint"; then
    spawn_checkpoint_status=1
  fi
fi
exec 8>&-
if [[ "$spawn_checkpoint_status" -ne 0 ]]; then
  exit 1
fi
if [[ -n "$pending_driver_signal" ]]; then
  exit "$pending_driver_signal"
fi
if [[ -n "$driver_wait_checkpoint" ]]; then
  CELESTIA_VERIFICATION_WAITING_DRIVER_PID=$driver_pid \
    "$driver_wait_checkpoint"
fi
while driver_job_owned "$driver_pid"; do
  sleep 0.05 || true
done
if wait "$driver_pid"; then
  status=0
else
  status=$?
fi
set +m
if [[ -n "$driver_completion_checkpoint" ]]; then
  if ! CELESTIA_VERIFICATION_COMPLETED_DRIVER_PID=$driver_pid \
    "$driver_completion_checkpoint"; then
    exit 1
  fi
fi
if [[ -n "$pending_driver_signal" ]] &&
  { [[ "$driver_signal_forwarded" == 1 ]] ||
    driver_job_owned "$driver_pid"; }; then
  exit "$pending_driver_signal"
fi
driver_pid=
driver_job=
driver_signal_pid=
exec 9<&-
exit "$status"
