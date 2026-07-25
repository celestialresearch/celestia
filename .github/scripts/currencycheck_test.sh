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
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/celestia-currencycheck.XXXXXX")
case "$work_dir" in
"${TMPDIR:-/tmp}"/celestia-currencycheck.*) ;;
*)
  printf 'refusing unexpected temporary path %s\n' "$work_dir" >&2
  exit 1
  ;;
esac
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
exceptions="$work_dir/exceptions"

expect_failure() {
  local expected=$1
  local output
  local status

  set +e
  output=$(
    CURRENCY_EXCEPTIONS_FILE="$exceptions" \
      bash "$root/.github/scripts/currencycheck.sh" verify 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'currency check accepted invalid exceptions\n' >&2
    return 1
  }
  grep -Fq "$expected" <<<"$output" || {
    printf 'currency check omitted %s:\n%s\n' "$expected" "$output" >&2
    return 1
  }
}

printf '%s\n' \
  'cargo|probe|1.0.0|2099-12-31|Compatibility requires the older API' \
  >"$exceptions"
CURRENCY_EXCEPTIONS_FILE="$exceptions" \
  bash "$root/.github/scripts/currencycheck.sh" verify
CURRENCY_EXCEPTIONS_FILE="$exceptions" \
  bash "$root/.github/scripts/currencycheck.sh" \
  allows cargo probe 1.0.0
if CURRENCY_EXCEPTIONS_FILE="$exceptions" \
  bash "$root/.github/scripts/currencycheck.sh" \
  allows cargo probe 2.0.0; then
  printf 'currency check allowed an unmatched version\n' >&2
  exit 1
fi

printf '%s\n' 'cargo|probe|1.0.0|2000-01-01|Expired' >"$exceptions"
expect_failure 'Expired currency exception'

printf '%s\n' 'unknown|probe|1.0.0|2099-12-31|Unknown ecosystem' >"$exceptions"
expect_failure 'Unknown currency exception ecosystem'

printf '%s\n' 'cargo|probe|1.0.0|not-a-date|Invalid date' >"$exceptions"
expect_failure 'Invalid currency exception expiry'

printf '%s\n' 'cargo|probe|1.0.0|2026-02-30|Normalised date' >"$exceptions"
expect_failure 'Invalid currency exception expiry'

printf '%s\n' 'cargo| probe|1.0.0|2099-12-31|Padded component' >"$exceptions"
expect_failure 'Malformed currency exception'

printf '%s\n' 'cargo|probe|1.0.0|2099-12-31|   ' >"$exceptions"
expect_failure 'Malformed currency exception'

printf '%s\n' \
  'cargo|probe|1.0.0|2099-12-31|First' \
  'cargo|probe|1.0.0|2099-12-31|Second' \
  >"$exceptions"
expect_failure 'Duplicate currency exception'
