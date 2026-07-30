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
trap 'rm -rf -- "$work_dir"' EXIT
trap 'exit 130' HUP INT TERM
calls_file="$work_dir/calls"
output_file="$work_dir/output"
error_file="$work_dir/error"
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

unset -f git
currency_file="$work_dir/currency"
currency_script="$work_dir/currencycheck.sh"
module_file="$work_dir/go.mod"
module_sum_file="$work_dir/go.sum"
action_file="$work_dir/action.yml"
printf 'exceptions-v1\n' >"$currency_file"
printf 'checker-v1\n' >"$currency_script"
printf 'module-v1\n' >"$module_file"
printf 'sum-v1\n' >"$module_sum_file"
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
printf 'module-v2\n' >"$module_file"
fourth_key=$(cache_key)
[[ "$third_key" != "$fourth_key" ]] || {
  printf 'action cache ignored the module manifest\n' >&2
  exit 1
}
printf 'sum-v2\n' >"$module_sum_file"
fifth_key=$(cache_key)
[[ "$fourth_key" != "$fifth_key" ]] || {
  printf 'action cache ignored the module checksum inventory\n' >&2
  exit 1
}
toolchain_dir="$work_dir/toolchain"
toolchain_value="$toolchain_dir/value"
mkdir -p "$toolchain_dir"
cat >"$toolchain_dir/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cat -- "$ACTIONCHECK_TEST_TOOLCHAIN_VALUE"
EOF
chmod 0700 "$toolchain_dir/go"
printf 'toolchain-v1\n' >"$toolchain_value"
original_path=$PATH
PATH="$toolchain_dir:$PATH"
export ACTIONCHECK_TEST_TOOLCHAIN_VALUE=$toolchain_value
sixth_key=$(cache_key)
printf 'toolchain-v2\n' >"$toolchain_value"
seventh_key=$(cache_key)
[[ "$sixth_key" != "$seventh_key" ]] || {
  printf 'action cache ignored the Go toolchain\n' >&2
  exit 1
}
PATH=$original_path
unset ACTIONCHECK_TEST_TOOLCHAIN_VALUE
cache_root="$work_dir/cache"
key=$(cache_key)
mkdir -p -- "$cache_root/actioncheck"
printf 'wrong-key\n' >"$cache_root/actioncheck/$key"
check_calls=0
original_check_actions=$(declare -f check_actions)
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
unset -f check_actions
eval "$original_check_actions"

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

invalid_entry='.github/workflows/main.yml:1:actions/checkout@0000000000000000000000000000000000000001 # v01.0.0'
if parse_action "$invalid_entry" >/dev/null 2>&1; then
  printf 'action parser accepted a non-canonical semantic version\n' >&2
  exit 1
fi

if parse_action '.github/workflows/main.yml:1:./local-action' \
  >/dev/null 2>&1; then
  printf 'action parser accepted an unresolved local action\n' >&2
  exit 1
fi

linked_action="$work_dir/linked-action.yml"
if ln -s "$action_file" "$linked_action" 2>/dev/null &&
  [[ -L "$linked_action" ]]; then
  original_action_files=$(declare -f action_files)
  action_files() {
    printf '%s\0' "$linked_action"
  }
  if action_documents <(action_files) >/dev/null 2>&1; then
    printf 'action document reader followed linked metadata\n' >&2
    exit 1
  fi
  eval "$original_action_files"
fi

if parse_action '.github/workflows/main.yml:1:docker://alpine:latest' \
  >/dev/null 2>&1; then
  printf 'action parser accepted a floating container image\n' >&2
  exit 1
fi
docker_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
if ! parse_action \
  ".github/workflows/main.yml:1:docker://alpine@sha256:$docker_digest"; then
  printf 'action parser rejected a digest-pinned container image\n' >&2
  exit 1
fi
[[ "$ACTION_KIND" == docker ]] || {
  printf 'action parser did not classify a container image\n' >&2
  exit 1
}

printf 'runs:\n  using: composite\n  steps:\n    - uses : example/action@main\n' >"$action_file"
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a spaced action key\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed a spaced unpinned action\n' >&2
  exit 1
fi

printf 'runs:\n  using: composite\n  steps:\n    - "uses": example/action@main\n' >"$action_file"
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a quoted action key\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed a quoted unpinned action\n' >&2
  exit 1
fi

printf 'runs:\n  using: composite\n  steps:\n    - { uses: example/action@main }\n' >"$action_file"
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a flow action mapping\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed a flow-mapped unpinned action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
runs:
  using: composite
  steps:
    - { uses: example/action@0000000000000000000000000000000000000001 } # v1.0.0
EOF
entry=$(remote_actions)
if ! parse_action "$entry"; then
  printf 'action parser rejected a flow-mapped pinned action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
jobs:
  call:
    "uses": example/workflow/.github/workflows/check.yml@main
EOF
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a reusable workflow\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed an unpinned reusable workflow\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
jobs:
  check:
    steps:
      - "uses": example/action@0000000000000000000000000000000000000001 # v1.0.0
EOF
entry=$(remote_actions)
if ! parse_action "$entry"; then
  printf 'action parser rejected a quoted pinned action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
jobs:
  check:
    container: alpine:latest
    services:
      database:
        image: postgres:latest
    steps:
      - uses: docker://busybox:latest
EOF
entries=$(remote_actions)
[[ "$(grep -Fc 'docker://' <<<"$entries")" -eq 3 ]] || {
  printf 'action inventory omitted a container reference\n' >&2
  exit 1
}
while IFS= read -r entry; do
  if parse_action "$entry" >/dev/null 2>&1; then
    printf 'action parser accepted an unpinned container reference\n' >&2
    exit 1
  fi
done <<<"$entries"

cat >"$action_file" <<EOF
runs:
  using: docker
  image: docker://alpine@sha256:$docker_digest
EOF
entry=$(remote_actions)
if ! parse_action "$entry"; then
  printf 'action parser rejected a digest-pinned Docker action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
image: &image alpine:latest
action: &action example/action@main
jobs:
  check:
    container: *image
    steps:
      - uses: *action
EOF
entries=$(remote_actions)
[[ "$(grep -Fc 'docker://alpine:latest' <<<"$entries")" -eq 1 &&
  "$(grep -Fc 'example/action@main' <<<"$entries")" -eq 1 ]] || {
  printf 'action inventory omitted an aliased reference\n' >&2
  exit 1
}

{
  printf 'level0: &level0 [value, value, value, value, value, value, value, value, value, value]\n'
  for level in 1 2 3 4 5 6 7; do
    printf 'level%s: &level%s [' "$level" "$level"
    item=0
    while ((item < 10)); do
      if ((item > 0)); then
        printf ', '
      fi
      printf '*level%s' "$((level - 1))"
      item=$((item + 1))
    done
    printf ']\n'
  done
} >"$action_file"
if remote_actions >"$output_file" 2>"$error_file"; then
  printf 'action parser accepted an excessive alias expansion\n' >&2
  exit 1
fi
grep -Fq 'traversal budget' "$error_file" || {
  printf 'action parser did not report its traversal bound\n' >&2
  exit 1
}

action_file="$work_dir/main.yml"
cat >"$action_file" <<'EOF'
permissions:
  security-events: write
jobs:
  classify:
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check accepted workflow-scoped security write\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions:
  "security-events": write
jobs:
  classify:
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check missed a quoted workflow permission\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions: write-all
jobs:
  classify:
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check accepted workflow-wide write authority\n' >&2
  exit 1
fi

for permission in contents id-token; do
  cat >"$action_file" <<EOF
permissions:
  $permission: write
EOF
  if check_permissions >/dev/null 2>&1; then
    printf 'permission check accepted %s write authority\n' "$permission" >&2
    exit 1
  fi
done

cat >"$action_file" <<'EOF'
permissions:
  contents: read
jobs:
  classify:
    permissions:
      security-events: write
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check accepted unrelated security write\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions:
  contents: read
jobs:
  classify:
    permissions:
      security-events: write # SARIF upload
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check missed an unrelated commented security write\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions:
  contents: read
jobs:
  analyze:
    permissions: &security-write
      security-events: write
    steps:
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000001 # v1.0.0
  classify:
    permissions: *security-write
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check missed aliased security write authority\n' >&2
  exit 1
fi

action_policy_dir="$work_dir/actionpolicy"
mkdir -p "$action_policy_dir"
cp -- "$root/tools/actionpolicy/main.go" "$action_policy_dir/main.go"
policy_files() {
  printf '%s\0' "$action_policy_dir/main.go"
}
first_key=$(cache_key)
printf '\n// cache mutation\n' >>"$action_policy_dir/main.go"
second_key=$(cache_key)
[[ "$first_key" != "$second_key" ]] || {
  printf 'action cache ignored the structural policy parser\n' >&2
  exit 1
}
