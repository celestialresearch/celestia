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
# shellcheck source=.github/scripts/actioncheck/fixture.sh
source "$script_dir/fixture.sh"
new_action_test_work
trap 'rm -rf -- "$work_dir"' EXIT
trap 'exit 130' HUP INT TERM

calls_file="$work_dir/calls"
output_file="$work_dir/output"
error_file="$work_dir/error"
action_file="$work_dir/action.yml"
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
  git_ls_remote --tags example.invalid >"$output_file" 2>"$error_file"
[[ "$(cat "$output_file")" == resolved && "$(cat "$calls_file")" -eq 3 ]] || {
  printf 'action remote lookup did not retry to success\n' >&2
  exit 1
}
[[ "$(grep -Fc 'Action remote lookup failed; retrying' "$error_file")" -eq 2 ]] || {
  printf 'action remote lookup omitted retry diagnostics\n' >&2
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
if check_actions false >/dev/null 2>&1; then
  printf 'action check ignored a failed file inventory\n' >&2
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
action_files() {
  printf '%s\0' "$action_file"
}
tag_sha() {
  case "$2" in
  v1.0.0) printf '%040d\n' 1 ;;
  v0.9.0) printf '%040d\n' 3 ;;
  *) return 1 ;;
  esac
}
latest_tag() {
  printf 'v1.0.0\n'
}
cat >"$action_file" <<'EOF'
jobs:
  first:
    uses: example/action@0000000000000000000000000000000000000001 # v1.0.0
  second:
    uses: example/action@0000000000000000000000000000000000000002 # v1.0.0
EOF
if check_actions true >/dev/null 2>&1; then
  printf 'action currency accepted a mismatched repeated release SHA\n' >&2
  exit 1
fi
cat >"$currency_script" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cat >"$action_file" <<'EOF'
jobs:
  first:
    uses: example/action@0000000000000000000000000000000000000001 # v1.0.0
  second:
    uses: example/action@0000000000000000000000000000000000000003 # v0.9.0
EOF
if check_actions true >/dev/null 2>&1; then
  printf 'action currency accepted an unexcepted repeated stale release\n' >&2
  exit 1
fi
