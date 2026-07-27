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

git_ls_remote() {
  printf '%s\n' \
    '0000000000000000000000000000000000000001 refs/tags/v0.0.0' \
    '0000000000000000000000000000000000000002 refs/tags/v01.0.0' \
    '0000000000000000000000000000000000000003 refs/tags/v9007199254740992.0.0' \
    '0000000000000000000000000000000000000004 refs/tags/v9007199254740993.0.0'
}
if [[ "$(latest_tag example.invalid)" != v9007199254740993.0.0 ]]; then
  printf 'action release selection mishandled exact semantic versions\n' >&2
  exit 1
fi

git_ls_remote() {
  printf '%s\n' \
    '0000000000000000000000000000000000000001 refs/tags/v0.0.0'
}
if [[ "$(latest_tag example.invalid)" != v0.0.0 ]]; then
  printf 'action release selection omitted v0.0.0\n' >&2
  exit 1
fi

unset -f git
currency_file="$work_dir/currency"
currency_script="$work_dir/currencycheck.sh"
action_file="$work_dir/action.yml"
printf 'exceptions-v1\n' >"$currency_file"
printf 'checker-v1\n' >"$currency_script"
printf 'uses: example/action@0000000000000000000000000000000000000001 # v1.0.0\n' >"$action_file"
action_files() {
  printf '%s\0' "$action_file"
}
first_key=$(cache_key)
printf 'exceptions-v2\n' >"$currency_file"
second_key=$(cache_key)
[[ "$first_key" != "$second_key" ]] || {
  printf 'action cache ignored currency exceptions\n' >&2
  exit 1
}
printf 'checker-v2\n' >"$currency_script"
third_key=$(cache_key)
[[ "$second_key" != "$third_key" ]] || {
  printf 'action cache ignored the currency checker\n' >&2
  exit 1
}
cache_root="$work_dir/cache"
key=$(cache_key)
mkdir -p -- "$cache_root/actioncheck"
printf 'wrong-key\n' >"$cache_root/actioncheck/$key"
check_calls=0
check_actions() {
  check_calls=$((check_calls + 1))
}
ACTIONCHECK_CACHE_MAX_AGE_MINUTES=1440 cached_currency >/dev/null
[[ "$check_calls" -eq 1 && "$(cat "$cache_root/actioncheck/$key")" == "$key" ]] || {
  printf 'action cache trusted an invalid marker\n' >&2
  exit 1
}
ACTIONCHECK_CACHE_MAX_AGE_MINUTES=1440 cached_currency >/dev/null
[[ "$check_calls" -eq 1 ]] || {
  printf 'action cache ignored a valid marker\n' >&2
  exit 1
}

invalid_entry='.github/workflows/main.yml:1:actions/checkout@0000000000000000000000000000000000000001 # v01.0.0'
if parse_action "$invalid_entry" >/dev/null 2>&1; then
  printf 'action parser accepted a non-canonical semantic version\n' >&2
  exit 1
fi
