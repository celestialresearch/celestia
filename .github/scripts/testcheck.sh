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
export GOWORK=off

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

mode=${1:-}
profile=${2:-}
fixture_mode=${3:-}
verification_repo=${4:-}
verification_prefix=${5:-}
cargo_bin=cargo
if [[ "$mode" == rust && "$fixture_mode" == --fixture ]]; then
  cargo_bin=${CARGO_BIN:-cargo}
elif [[ "$mode" == rust && -n "${CARGO_BIN+x}" ]]; then
  printf 'CARGO_BIN is permitted only in fixture mode\n' >&2
  exit 2
fi
work=${TMPDIR:-.cache}
mkdir -p "$work"
temporary=$(mktemp -d "$work/test-completion.XXXXXX")

cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

go_inventory() {
  if [[ "$fixture_mode" == --fixture ]]; then
    [[ -n "${TESTINVENTORY_BIN:-}" ]] || return 2
    "$TESTINVENTORY_BIN" go >"$temporary/expected"
  else
    go run ./tools/sourcepolicy go-test-inventory >"$temporary/expected"
  fi
}

cargo_executables() {
  if [[ "$fixture_mode" == --fixture ]]; then
    [[ -n "${TESTINVENTORY_BIN:-}" ]] || return 2
    "$TESTINVENTORY_BIN" cargo
  else
    go run ./tools/sourcepolicy cargo-test-inventory
  fi
}

shell_path() {
  case "$1" in
  [A-Za-z]:\\*)
    command -v cygpath >/dev/null 2>&1 || return 1
    cygpath -u -- "$1"
    ;;
  *) printf '%s\n' "$1" ;;
  esac
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
  LC_ALL=C sort -u "$temporary/observed" -o "$temporary/observed"
  missing=$(LC_ALL=C comm -23 "$temporary/expected" "$temporary/observed")
  if [[ -n "$missing" ]]; then
    printf 'Go tests lacked terminal outcomes:\n%s\n' "$missing" >&2
    return 1
  fi
}

rust_command() {
  local all_targets=$1
  local arguments=(test --workspace --all-features --locked --no-run --message-format=json)
  local directory
  local executable
  local test_name

  if [[ "$all_targets" == true ]]; then
    arguments=(test --workspace --all-features --all-targets --locked --no-run --message-format=json)
  fi
  "$cargo_bin" "${arguments[@]}" |
    cargo_executables >"$temporary/rust-executables"
  while IFS=$'\t' read -r directory executable; do
    directory=$(shell_path "$directory")
    executable=$(shell_path "$executable")
    (
      cd -- "$directory"
      "$executable" --list --format terse
    ) >"$temporary/rust-list"
    while IFS= read -r test_name; do
      test_name=${test_name%: test}
      [[ "$test_name" == *": benchmark" ]] && continue
      if ! (
        cd -- "$directory"
        "$executable" --exact "$test_name" --test-threads=1
      ) >"$temporary/rust-result" 2>&1; then
        cat "$temporary/rust-result"
        return 1
      fi
      cat "$temporary/rust-result"
      if [[ $(grep -c '^test result: ok\.' \
        "$temporary/rust-result" || true) -ne 1 ]]; then
        printf 'Rust test executable lacked one terminal summary: %s\n' \
          "$executable" >&2
        return 1
      fi
    done <"$temporary/rust-list"
  done <"$temporary/rust-executables"
  "$cargo_bin" test --workspace --all-features --locked
}

rust_tests() {
  rust_command true
}

verification_tests() {
  local directory=$profile
  local executed=$fixture_mode
  local family
  local mode
  local repository=$verification_repo
  local prefix=$verification_prefix

  if [[ ! -d "$directory" || ! -f "$executed" ||
    ! -d "$repository" || -z "$prefix" ]]; then
    printf 'Usage: testcheck.sh verification FAMILY_DIR EXECUTED\n' >&2
    return 2
  fi
  cat >"$temporary/expected" <<'EOF'
lint_test.sh
action_test.sh
rust_config_test.sh
rust_artefact_test.sh
coverage_test.sh
source_policy_test.sh
licence_test.sh
release_artefact_test.sh
EOF
  while IFS= read -r family; do
    mode=$(git -C "$repository" ls-files --stage -- "$prefix/$family")
    if [[ ! -f "$directory/$family" || "${mode%% *}" != 100755 ]]; then
      printf 'verification family is unavailable: %s\n' "$family" >&2
      return 1
    fi
  done <"$temporary/expected"
  find "$directory" -type f -name '*_test.sh' -exec basename {} \; |
    LC_ALL=C sort >"$temporary/available"
  LC_ALL=C sort "$temporary/expected" >"$temporary/expected-sorted"
  if ! cmp -s "$temporary/expected-sorted" "$temporary/available"; then
    printf 'verification family inventory differs\n' >&2
    return 1
  fi
  if ! cmp -s "$temporary/expected" "$executed"; then
    printf 'verification families lacked ordered execution\n' >&2
    return 1
  fi
}

case "$mode" in
go) go_tests ;;
rust) rust_tests ;;
verification) verification_tests ;;
*)
  printf 'Usage: testcheck.sh go quick|race|standard | rust | verification FAMILY_DIR EXECUTED\n' >&2
  exit 2
  ;;
esac
