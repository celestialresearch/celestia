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

verification_temp_root=${CELESTIA_VERIFICATION_TMPDIR:-${TMPDIR:-/tmp}}

verification_process_running() {
  local pid=$1
  local state

  kill -0 "$pid" 2>/dev/null || return 1
  if state=$(ps -o stat= -p "$pid" 2>/dev/null); then
    state=${state//[[:space:]]/}
    [[ "$state" == Z* ]] && return 1
  fi
  return 0
}

verification_group_zombies() {
  local state
  local states
  local pid=$1

  [[ "$(uname -s 2>/dev/null)" == Linux ]] || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  states=$(ps -eo pgid=,stat= 2>/dev/null |
    awk -v pgid="$pid" '$1 == pgid { print $2 }') || return 1
  [[ -n "$states" && "${#states}" -le 4096 ]] || return 1
  while IFS= read -r state; do
    state=${state//[[:space:]]/}
    [[ "$state" == Z* ]] || return 1
  done <<<"$states"
}

verification_snapshot_source_available() {
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

verification_snapshot_size() {
  local size

  size=$(wc -c <"$1") || return 1
  size=${size//[[:space:]]/}
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$size"
}

verification_snapshot_matches() {
  local path=$1
  local expected_size=$2
  local expected_identity=$3
  local identity
  local size

  [[ ! -L "$path" && -f "$path" ]] || return 1
  size=$(verification_snapshot_size "$path") || return 1
  [[ "$size" == "$expected_size" ]] || return 1
  identity=$(git hash-object --no-filters -- "$path") || return 1
  [[ "$identity" == "$expected_identity" ]]
}

create_verification_symlink() {
  local object
  local path=$2
  local repository=$1
  local target=$3

  git -C "$repository" config core.symlinks true
  object=$(printf '%s' "$target" | git -C "$repository" hash-object -w --stdin)
  git -C "$repository" update-index --add \
    --cacheinfo "120000,$object,$path"
  git -C "$repository" checkout-index --force -- "$path"
  [[ -L "$repository/$path" ]] || {
    printf 'failed to create verification symlink: %s\n' "$path" >&2
    return 1
  }
}

require_empty_verification_directory() {
  local contents
  local directory=$1
  local owner=$2

  [[ -d "$directory" ]] || {
    printf '%s directory is unavailable\n' "$owner" >&2
    return 1
  }
  contents=$(find "$directory" -mindepth 1 -print -quit) || {
    printf '%s directory is uninspectable\n' "$owner" >&2
    return 1
  }
  [[ -z "$contents" ]] || {
    printf '%s retained temporary state after failure\n' "$owner" >&2
    return 1
  }
}

new_verification_work() {
  local name=$1
  local root
  local work

  mkdir -p "$verification_temp_root"
  root=$(cd "$verification_temp_root" && pwd -P)
  work=$(mktemp -d "$root/celestia-${name}.XXXXXX")
  case "$work" in
  "$root"/celestia-"$name".*) printf '%s\n' "$work" ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$work" >&2
    return 1
    ;;
  esac
}
terminate_child() {
  local pid=$1

  kill -0 "$pid" 2>/dev/null || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

cleanup_verification() {
  local work_dir=$1
  shift

  for pid in "$@"; do
    if [[ -n "$pid" ]]; then
      terminate_child "$pid"
    fi
  done
  rm -rf -- "$work_dir"
}

await_child() {
  local name=$1
  local pid=$2
  local result

  set +e
  wait "$pid"
  result=$?
  set -e
  if ((result != 0)); then
    printf '%s self-test failed with status %d\n' "$name" "$result" >&2
    return 1
  fi
}
