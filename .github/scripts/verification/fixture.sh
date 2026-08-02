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
