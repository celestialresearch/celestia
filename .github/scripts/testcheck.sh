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

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

mode=${1:-}
profile=${2:-}
work=${TMPDIR:-.cache}
mkdir -p "$work"
temporary=$(mktemp -d "$work/test-completion.XXXXXX")

cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

go_inventory() {
  if [[ -n "${TESTINVENTORY_BIN:-}" ]]; then
    "$TESTINVENTORY_BIN" go >"$temporary/expected"
  else
    go run ./tools/sourcepolicy go-test-inventory >"$temporary/expected"
  fi
}

cargo_executables() {
  if [[ -n "${TESTINVENTORY_BIN:-}" ]]; then
    "$TESTINVENTORY_BIN" cargo
  else
    go run ./tools/sourcepolicy cargo-test-inventory
  fi
}

go_tests() {
  local arguments=()
  local missing

  case "$profile" in
  quick) arguments=(-p=2) ;;
  standard) arguments=(-p=2 -count=1 -shuffle=on) ;;
  race) arguments=(-p=2 -race -count=1 -shuffle=on) ;;
  *)
    printf 'Usage: testcheck.sh go quick|race|standard\n' >&2
    return 2
    ;;
  esac

  go_inventory
  : >"$temporary/observed"
  go test -json "${arguments[@]}" ./... |
    awk -v observed="$temporary/observed" '
      {
        print
        if ($0 !~ /"Test":"/ ||
            $0 !~ /"Action":"(pass|fail|skip)"/) {
          next
        }
        package_name = $0
        sub(/^.*"Package":"/, "", package_name)
        sub(/".*$/, "", package_name)
        test_name = $0
        sub(/^.*"Test":"/, "", test_name)
        sub(/".*$/, "", test_name)
        if (test_name !~ /\//) {
          print package_name "\t" test_name >> observed
        }
        if ($0 ~ /"Action":"skip"/) {
          skipped = 1
        } else if ($0 ~ /"Action":"fail"/) {
          failed = 1
        }
      }
      END {
        if (skipped) {
          print "Go test execution contained a skipped case"
          exit 1
        }
        if (failed) {
          print "Go test execution contained a failed case"
          exit 1
        }
      }
    '
  sort -u "$temporary/observed" -o "$temporary/observed"
  missing=$(comm -23 "$temporary/expected" "$temporary/observed")
  if [[ -n "$missing" ]]; then
    printf 'Go tests lacked terminal outcomes:\n%s\n' "$missing" >&2
    return 1
  fi
}

rust_command() {
  local all_targets=$1
  local arguments=(test --workspace --locked --no-run --message-format=json)
  local executable
  local test_name

  if [[ "$all_targets" == true ]]; then
    arguments=(test --workspace --all-targets --locked --no-run --message-format=json)
  fi
  "${CARGO_BIN:-cargo}" "${arguments[@]}" |
    cargo_executables >"$temporary/rust-executables"
  while IFS= read -r executable; do
    "$executable" --list --format terse >"$temporary/rust-list"
    while IFS= read -r test_name; do
      test_name=${test_name%: test}
      [[ "$test_name" == *": benchmark" ]] && continue
      "$executable" --exact "$test_name" --test-threads=1
    done <"$temporary/rust-list"
  done <"$temporary/rust-executables"
}

rust_tests() {
  "${CARGO_BIN:-cargo}" clippy --workspace --all-targets --locked -- \
    -D warnings -D clippy::exit
  rust_command false
  rust_command true
  "${CARGO_BIN:-cargo}" test --workspace --locked
}

case "$mode" in
go) go_tests ;;
rust) rust_tests ;;
*)
  printf 'Usage: testcheck.sh go quick|race|standard | rust\n' >&2
  exit 2
  ;;
esac
