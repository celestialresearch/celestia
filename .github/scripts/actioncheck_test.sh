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

# shellcheck source=.github/scripts/actioncheck.sh
source "$root/.github/scripts/actioncheck.sh"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/celestia-actioncheck.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
calls_file="$work_dir/calls"
output_file="$work_dir/output"
printf '0\n' >"$calls_file"

git() {
  local calls
  calls=$(cat "$calls_file")
  calls=$((calls + 1))
  printf '%d\n' "$calls" >"$calls_file"
  if ((calls < 3)); then
    printf 'old-partial\n'
    return 1
  fi
  printf 'resolved\n'
}

ACTIONCHECK_REMOTE_ATTEMPTS=3 \
  ACTIONCHECK_RETRY_DELAY_SECONDS=0 \
  git_ls_remote --tags example.invalid >"$output_file"
[[ "$(cat "$output_file")" == resolved && "$(cat "$calls_file")" -eq 3 ]] || {
  printf 'action remote lookup did not retry to success\n' >&2
  exit 1
}

printf '0\n' >"$calls_file"
if ACTIONCHECK_REMOTE_ATTEMPTS=2 \
  ACTIONCHECK_RETRY_DELAY_SECONDS=0 \
  git_ls_remote --tags example.invalid >/dev/null 2>&1; then
  printf 'action remote lookup accepted exhausted retries\n' >&2
  exit 1
fi
[[ "$(cat "$calls_file")" -eq 2 ]] || {
  printf 'action remote lookup exceeded its retry bound\n' >&2
  exit 1
}

if ACTIONCHECK_REMOTE_ATTEMPTS=0 \
  git_ls_remote --tags example.invalid >/dev/null 2>&1; then
  printf 'action remote lookup accepted an invalid retry bound\n' >&2
  exit 1
fi

action_files() {
  return 2
}
if remote_actions >/dev/null 2>&1; then
  printf 'action parsing ignored a failed file inventory\n' >&2
  exit 1
fi
if cache_key >/dev/null 2>&1; then
  printf 'action cache ignored a failed file inventory\n' >&2
  exit 1
fi
