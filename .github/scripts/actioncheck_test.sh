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

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
finish_action_driver() {
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "${driver_pid:-}" ]]; then
    kill -TERM -- "-$driver_pid" 2>/dev/null || true
    kill -KILL -- "-$driver_pid" 2>/dev/null || true
    wait "$driver_pid" 2>/dev/null || true
    driver_pid=
  fi
  exit "$status"
}

main() (
  local executed
  local family
  local planned

  executed=$(mktemp "${TMPDIR:-/tmp}/celestia-action-families.XXXXXX")
  planned="$executed.planned"
  trap 'rm -f -- "$executed" "$planned"' EXIT
  printf '%s\n' "$families" >"$planned"
  bash "$root/.github/scripts/testcheck.sh" action "$family_dir" "$planned" \
    "$family_repo" "$family_prefix"

  : >"$executed"
  while IFS= read -r family; do
    bash "$family_dir/$family"
    printf '%s\n' "$family" >>"$executed"
  done <<<"$families"

  bash "$root/.github/scripts/testcheck.sh" action "$family_dir" "$executed" \
    "$family_repo" "$family_prefix"
)

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
driver_pid=
exit "$status"
