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
