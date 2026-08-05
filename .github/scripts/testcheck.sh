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
go_coverage_profile=
if [[ "$mode" == go && "$profile" == standard && "$fixture_mode" != --fixture ]]; then
  go_coverage_profile=$fixture_mode
  fixture_mode=${4:-}
fi
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

select_quick_go_path() {
  local architecture
  local constrained
  local directory
  local filename
  local operating_system
  local path=$1
  local status=$2
  local target

  case "$path" in
  README.md | docs/*) return ;;
  *.go) ;;
  *) return 1 ;;
  esac
  case "$status:$path" in
  [AM]:*_test.go) ;;
  [AM]:internal/operation/urlreference/transform/*.go) ;;
  *) return 1 ;;
  esac
  directory=${path%/*}
  [[ "$directory" != "$path" ]] || return 1
  if grep -Eq '^(//go:build|//[[:space:]]*\+build)' -- "$path"; then
    return 1
  fi
  filename=${path##*/}
  constrained=${filename%_test.go}.go
  while IFS= read -r target; do
    operating_system=${target%/*}
    architecture=${target#*/}
    case "$constrained" in
    *_"$operating_system".go | *_"$architecture".go | \
      *_"$operating_system"_"$architecture".go) return 1 ;;
    esac
  done <<<"$quick_platforms"
  if [[ "$path" == *_test.go ]]; then
    printf '%s/%s\n' "$quick_module" "$directory" >>"$temporary/quick-direct"
    return
  fi
  printf '%s/%s\n' "$quick_module" "$directory" >>"$temporary/quick-propagate"
}

expand_quick_go_packages() {
  if ! go list -f '{{.ImportPath}}	{{join .Imports " "}}' ./... >"$temporary/quick-graph"; then
    return 1
  fi
  awk -F '\t' -v direct_file="$temporary/quick-direct" \
    -v propagate_file="$temporary/quick-propagate" '
    FILENAME == direct_file { direct[$1] = 1; next }
    FILENAME == propagate_file { selected[$1] = 1; next }
    {
      package_name[NR] = $1
      imports[NR] = $2
      known[$1] = 1
    }
    END {
      changed = 1
      while (changed) {
        changed = 0
        for (line in package_name) {
          if (package_name[line] in selected) continue
          count = split(imports[line], values, " ")
          for (item = 1; item <= count; item++) {
            if (values[item] in selected) {
              selected[package_name[line]] = 1
              changed = 1
              break
            }
          }
        }
      }
      for (name in direct) {
        if (!(name in known)) exit 2
        selected[name] = 1
      }
      for (name in selected) {
        if (!(name in known)) exit 2
        print name
      }
    }
  ' "$temporary/quick-direct" "$temporary/quick-propagate" \
    "$temporary/quick-graph" | LC_ALL=C sort
  [[ "${PIPESTATUS[0]}" == 0 ]]
}

quick_go_packages() {
  local base
  local path
  local status

  if [[ "$fixture_mode" == --fixture ]]; then
    printf './...\n'
    return
  fi
  if git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null; then
    base=$(git merge-base HEAD refs/remotes/origin/main) || {
      printf './...\n'
      return
    }
  else
    base=HEAD
  fi
  if ! git diff --no-renames --name-status -z "$base" -- >"$temporary/changes" ||
    ! git ls-files --others --exclude-standard -z >"$temporary/untracked"; then
    printf './...\n'
    return
  fi
  quick_module=$(go list -m -f '{{.Path}}') || {
    printf './...\n'
    return
  }
  quick_platforms=$(go tool dist list) || {
    printf './...\n'
    return
  }
  : >"$temporary/quick-direct"
  : >"$temporary/quick-propagate"
  while IFS= read -r -d '' status && IFS= read -r -d '' path; do
    select_quick_go_path "$path" "$status" || {
      printf './...\n'
      return
    }
  done <"$temporary/changes"
  while IFS= read -r -d '' path; do
    select_quick_go_path "$path" A || {
      printf './...\n'
      return
    }
  done <"$temporary/untracked"
  if [[ ! -s "$temporary/quick-direct" && ! -s "$temporary/quick-propagate" ]]; then
    return
  fi
  if ! expand_quick_go_packages; then
    printf './...\n'
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
  local coverage_profile=$go_coverage_profile
  local finished
  local arguments=()
  local missing
  local started
  local package
  local packages=()

  case "$profile" in
  quick)
    arguments=(-p=2)
    while IFS= read -r package; do
      [[ -n "$package" ]] && packages+=("$package")
    done < <(quick_go_packages)
    if ((${#packages[@]} == 0)); then
      printf 'No changed Go packages require tests.\n'
      return
    fi
    ;;
  standard)
    arguments=(-p=2 -count=1 -shuffle=on)
    if [[ -n "$coverage_profile" ]]; then
      case "$(uname -s 2>/dev/null)" in
      CYGWIN*) coverage_profile=$(cygpath -w "$coverage_profile") ;;
      esac
      arguments+=(-covermode=atomic "-coverprofile=$coverage_profile")
    fi
    ;;
  race) arguments=(-p=2 -race -count=1 -shuffle=on) ;;
  *)
    printf 'Usage: testcheck.sh go quick|race|standard\n' >&2
    return 2
    ;;
  esac
  ((${#packages[@]} > 0)) || packages=(./...)

  started=$(date +%s)
	if ! go_inventory; then
    printf '        %-34s[FAIL] %ss\n' 'Go Test Discovery' \
      "$(($(date +%s) - started))"
    return 1
	fi
	if [[ "$profile" == quick && "${packages[0]}" != ./... ]]; then
		printf '%s\n' "${packages[@]}" | LC_ALL=C sort -u >"$temporary/quick-packages"
		awk -F '\t' 'NR == FNR { selected[$1] = 1; next }
		  selected[$1] { print }' "$temporary/quick-packages" \
		  "$temporary/expected" >"$temporary/quick-expected"
		mv -- "$temporary/quick-expected" "$temporary/expected"
	fi
  printf '        %-34s[PASS] %ss\n' 'Go Test Discovery' \
    "$(($(date +%s) - started))"
  : >"$temporary/observed"
  started=$(date +%s)
  if ! go test -json "${arguments[@]}" "${packages[@]}" |
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
    '; then
    printf '        %-34s[FAIL] %ss\n' 'Go Test Execution' \
      "$(($(date +%s) - started))"
    return 1
  fi
  finished=$(date +%s)
  printf '        %-34s[PASS] %ss\n' 'Go Test Execution' \
    "$((finished - started))"
  LC_ALL=C sort -u "$temporary/observed" -o "$temporary/observed"
  if ! missing=$(LC_ALL=C comm -23 \
    "$temporary/expected" "$temporary/observed"); then
    printf 'Go test inventory comparison failed\n' >&2
    return 1
  fi
  if [[ -n "$missing" ]]; then
    printf 'Go tests lacked terminal outcomes:\n%s\n' "$missing" >&2
    return 1
  fi
}

go_fuzz() {
  local count=0
  local discovery_output
  local discovery_started
  local entry
  local fuzz_time=${DEVCHECK_FUZZTIME:-1000x}
  local package
  local started
  local target
  local timeout=${DEVCHECK_FUZZ_TIMEOUT:-60s}

  discovery_started=$(date +%s)
  if ! discovery_output=$(go run ./tools/sourcepolicy go-fuzz-inventory); then
    printf 'Go fuzz-target discovery failed.\n'
    return 1
  fi
  printf '        %-34s[PASS] %ss\n' 'Fuzz Discovery' \
    "$(($(date +%s) - discovery_started))"
  if [[ -z "$discovery_output" ]]; then
    printf 'No Go fuzz targets discovered.\n'
    return
  fi
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    count=$((count + 1))
    IFS=$'\t' read -r package target <<<"$entry"
    started=$(date +%s)
    if go test -run '^$' -fuzz "^${target}$" -fuzztime "$fuzz_time" \
      -timeout "$timeout" "$package"; then
      printf '        %-34s[PASS] %ss\n' "$target" \
        "$(($(date +%s) - started))"
    else
      printf '        %-34s[FAIL] %ss\n' "$target" \
        "$(($(date +%s) - started))"
      return 1
    fi
  done <<<"$discovery_output"
  printf 'Discovered %s Go fuzz target(s).\n' "$count"
}

rust_tests() {
  local arguments=(test --workspace --all-features --all-targets --locked --no-run --message-format=json)
  local directory
  local executable
  local started
  local test_name

  started=$(date +%s)
  if ! "$cargo_bin" "${arguments[@]}" |
    cargo_executables >"$temporary/rust-executables"; then
    printf '        %-34s[FAIL] %ss\n' 'Rust Test Construction' \
      "$(($(date +%s) - started))"
    return 1
  fi
  printf '        %-34s[PASS] %ss\n' 'Rust Test Construction' \
    "$(($(date +%s) - started))"
  started=$(date +%s)
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
      if [[ $(grep -c '^test result: ok\.' \
        "$temporary/rust-result" || true) -ne 1 ]]; then
        printf 'Rust test executable lacked one terminal summary: %s\n' \
          "$executable" >&2
        cat "$temporary/rust-result" >&2
        return 1
      fi
    done <"$temporary/rust-list"
  done <"$temporary/rust-executables"
  printf '        %-34s[PASS] %ss\n' 'Rust Test Execution' \
    "$(($(date +%s) - started))"
}

family_inventory() {
  local directory=$1
  local pattern=$2
  local output=$3
  local owner=$4
  local name
  local path

  if ! find "$directory" -name "$pattern" -print0 >"$temporary/candidates"; then
    printf 'failed to inventory %s\n' "$owner" >&2
    return 1
  fi
  : >"$output"
  while IFS= read -r -d '' path; do
    if [[ -L "$path" || ! -f "$path" ]]; then
      printf '%s is unavailable: %s\n' "$owner" "$path" >&2
      return 1
    fi
    name=${path##*/}
    case "$name" in
    *$'\n'* | *$'\r'*)
      printf '%s has an unsupported name\n' "$owner" >&2
      return 1
      ;;
    esac
    printf '%s\n' "$name" >>"$output"
  done <"$temporary/candidates"
  LC_ALL=C sort -o "$output" "$output"
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
devcheck_config_test.sh
rust_config_test.sh
rust_integration_test.sh
rust_artefact_test.sh
coverage_test.sh
source_policy_test.sh
licence_test.sh
release_artefact_test.sh
EOF
  while IFS= read -r family; do
    mode=$(git -C "$repository" ls-files --stage -- "$prefix/$family")
    if [[ -L "$directory/$family" || ! -f "$directory/$family" || "${mode%% *}" != 100755 ]]; then
      printf 'verification family is unavailable: %s\n' "$family" >&2
      return 1
    fi
  done <"$temporary/expected"
  family_inventory "$directory" '*_test.sh' "$temporary/available" \
    'verification family'
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

action_tests() {
  local directory=$profile
  local executed=$fixture_mode
  local family
  local mode
  local repository=$verification_repo
  local prefix=$verification_prefix

  if [[ ! -d "$directory" || ! -f "$executed" ||
    ! -d "$repository" || -z "$prefix" ]]; then
    printf 'Usage: testcheck.sh action FAMILY_DIR EXECUTED REPO PREFIX\n' >&2
    return 2
  fi
  cat >"$temporary/expected" <<'EOF'
remote_release_test.sh
cache_test.sh
inventory_test.sh
permissions_test.sh
EOF
  while IFS= read -r family; do
    mode=$(git -C "$repository" ls-files --stage -- "$prefix/$family")
    if [[ -L "$directory/$family" || ! -f "$directory/$family" || "${mode%% *}" != 100755 ]]; then
      printf 'action test family is unavailable: %s\n' "$family" >&2
      return 1
    fi
  done <"$temporary/expected"
  family_inventory "$directory" '*_test.sh' "$temporary/available" \
    'action test family'
  LC_ALL=C sort "$temporary/expected" >"$temporary/expected-sorted"
  if ! cmp -s "$temporary/expected-sorted" "$temporary/available"; then
    printf 'action test family inventory differs\n' >&2
    return 1
  fi
  if ! cmp -s "$temporary/expected" "$executed"; then
    printf 'action test families lacked ordered execution\n' >&2
    return 1
  fi
}

case "$mode" in
go)
  if [[ "$profile" == fuzz ]]; then
    go_fuzz
  else
    go_tests
  fi
  ;;
go-packages) quick_go_packages ;;
rust) rust_tests ;;
verification) verification_tests ;;
action) action_tests ;;
*)
  printf 'Usage: testcheck.sh go fuzz|quick|race|standard | go-packages | rust | verification FAMILY_DIR EXECUTED | action FAMILY_DIR EXECUTED REPO PREFIX\n' >&2
  exit 2
  ;;
esac
