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
crate_versions="$work_dir/crate-versions"

celestia_test_rustup() {
  printf '%s\n' "${RUSTUP_TEST_OUTPUT:-}"
  return "${RUSTUP_TEST_STATUS:-0}"
}

celestia_test_cargo() {
  component=${2:-}
  version=$(awk -F'|' -v component="$component" '$1 == component { print $2; exit }' \
    "$CARGO_TEST_VERSIONS")
  [ -n "$version" ] || return 1
  printf '%s = "%s" # fixture\n' "$component" "$version"
}

export -f celestia_test_rustup celestia_test_cargo

awk '
  /^\[workspace.dependencies\]$/ { active = 1; next }
  active && /^\[/ { exit }
  active && /^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]*=/ {
    line = $0
    sub(/^[[:space:]]*/, "", line)
    name = line
    sub(/[[:space:]]*=.*$/, "", name)
    pending = name
  }
  active && pending != "" {
    line = $0
    if (match(line, /version[[:space:]]*=[[:space:]]*"=[^"]+"/)) {
      value = substr(line, RSTART, RLENGTH)
      sub(/^.*"=/, "", value)
      sub(/"$/, "", value)
      print pending "|" value
      pending = ""
    } else if (match(line, /=[[:space:]]*"=[^"]+"/)) {
      value = substr(line, RSTART, RLENGTH)
      sub(/^.*"=/, "", value)
      sub(/"$/, "", value)
      print pending "|" value
      pending = ""
    } else if (line ~ /}/) {
      pending = ""
    }
  }
' "$root/Cargo.toml" >"$crate_versions"
sed -n \
  's/^[[:space:]]*\(cargo-[a-z0-9-]*\)@\([^[:space:]]*\).*$/\1|\2/p' \
  "$root/.github/workflows/main.yml" >>"$crate_versions"

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

expect_toolchain() {
  local output=$1
  local expected=$2
  local fixture_status=${3:-0}
  local status
  local result

  set +e
  result=$(
      RUSTUP_BIN=celestia_test_rustup \
      RUSTUP_TEST_OUTPUT="$output" \
      RUSTUP_TEST_STATUS="$fixture_status" \
      CARGO_BIN=celestia_test_cargo \
      CARGO_TEST_VERSIONS="$crate_versions" \
      CURRENCY_EXCEPTIONS_FILE="$exceptions" \
      bash "$root/.github/scripts/currencycheck.sh" currency 2>&1
  )
  status=$?
  set -e
  if [[ "$expected" == pass ]]; then
    [[ "$status" -eq 0 ]] || {
      printf 'toolchain currency check failed:\n%s\n' "$result" >&2
      return 1
    }
  else
    [[ "$status" -ne 0 ]] || {
      printf 'toolchain currency check accepted invalid output\n' >&2
      return 1
    }
    grep -Fq "$expected" <<<"$result" || {
      printf 'toolchain currency check omitted %s:\n%s\n' \
        "$expected" "$result" >&2
      return 1
    }
  fi
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

current=$(awk -F'"' '$1 ~ /^[[:space:]]*channel/ { print $2; exit }' \
  "$root/rust-toolchain.toml")
printf '%s\n' \
  "toolchain|rust|$current|2099-12-31|Test fixture permits the current toolchain" \
  >"$exceptions"
expect_toolchain \
  'stable-x86_64-pc-windows-msvc - up to date : 1.94.1 (e408947bf 2026-03-25)' \
  pass
expect_toolchain \
  'stable-x86_64-pc-windows-msvc - Up To Date: 1.94.1 (e408947bf 2026-03-25)' \
  pass
expect_toolchain \
  'stable-x86_64-pc-windows-msvc - Update Available : 1.94.1 (...) -> 1.95.0 (...)' \
  pass \
  100
expect_toolchain 'stable toolchain status unknown' \
  'Could not determine the latest stable Rust toolchain'
expect_toolchain \
  'stable-x86_64-pc-windows-msvc - Update Available : 1.94.1 (...) -> 1.95.0 (...)' \
  'Rust toolchain currency check failed' \
  1

set +e
result=$(
  RUSTUP_BIN=celestia_test_rustup \
  RUSTUP_TEST_STATUS=1 \
  RUSTUP_TEST_OUTPUT='rustup failed' \
  CARGO_BIN=celestia_test_cargo \
  CARGO_TEST_VERSIONS="$crate_versions" \
    CURRENCY_EXCEPTIONS_FILE="$exceptions" \
    bash "$root/.github/scripts/currencycheck.sh" currency 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'toolchain currency check accepted command failure\n' >&2
  exit 1
}
grep -Fq 'Rust toolchain currency check failed: rustup failed' <<<"$result" || {
  printf 'toolchain currency check hid command failure:\n%s\n' "$result" >&2
  exit 1
}
