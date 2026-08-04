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

policy=.github/.coverage
max_failure_output_bytes=65536

usage() {
  printf 'Usage: %s verify\n' "${0##*/}" >&2
}

load_policy() {
  local configured first second third extra

  default_floor=
  package_floors=
  while read -r first second third extra; do
    [[ -n "${first:-}" ]] || continue
    [[ "$first" != \#* ]] || continue
    [[ -z "${extra:-}" ]] || {
      printf '%s: invalid coverage policy entry\n' "$policy" >&2
      return 2
    }
    case "$first" in
    default)
      [[ -z "${third:-}" && -z "$default_floor" ]] || return 2
      default_floor=$second
      ;;
    package)
      [[ -n "${second:-}" && -n "${third:-}" ]] || return 2
      while read -r configured _; do
        [[ -n "${configured:-}" ]] || continue
        if [[ "$configured" == "$second" ]]; then
          printf '%s: duplicate coverage policy for %s\n' \
            "$policy" "$second" >&2
          return 2
        fi
      done <<<"$package_floors"
      package_floors+="$second $third"$'\n'
      ;;
    *)
      printf '%s: unknown coverage policy key %s\n' "$policy" "$first" >&2
      return 2
      ;;
    esac
  done <"$policy"

  validate_percentage "$default_floor" default
  while read -r first second; do
    [[ -n "${first:-}" ]] || continue
    validate_percentage "$second" "$first"
  done <<<"$package_floors"
}

validate_percentage() {
  local value=$1
  local label=$2

  awk -v value="$value" 'BEGIN {
    exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value >= 0 && value <= 100)
  }' || {
    printf '%s: invalid coverage floor for %s\n' "$policy" "$label" >&2
    return 2
  }
}

create_report() {
  local profile=$1
  local report=$2
  local packages=$3
  local failure_output=$4
  local go_profile=$profile
  local package_file

  case "$(uname -s 2>/dev/null)" in
  CYGWIN*) go_profile=$(cygpath -w "$profile") ;;
  esac
  : >"$report"
  package_file=$report.packages
  printf '%s\n' "$packages" >"$package_file"
  if ! go test -p=1 -count=1 -covermode=atomic \
    -coverprofile="$go_profile" ./... 2>&1 |
    tail -c "$max_failure_output_bytes" >"$failure_output"; then
    printf 'coverage tests failed (last %s bytes):\n' \
      "$max_failure_output_bytes" >&2
    cat "$failure_output" >&2
    rm -f -- "$package_file"
    return 1
  fi
  awk -v package_file="$package_file" '
    BEGIN {
      while ((getline package < package_file) > 0) {
        packages[++package_count] = package
      }
      close(package_file)
    }
    NR == 1 { next }
    {
      source = $1
      sub(/:[0-9]+[.][0-9]+,.*/, "", source)
      owner = ""
      for (item = 1; item <= package_count; item++) {
        candidate = packages[item]
        if (length(candidate) > length(owner) &&
            substr(source, 1, length(candidate) + 1) == candidate "/") {
          owner = candidate
        }
      }
      if (owner == "") {
        print "coverage profile names an unknown package: " source > "/dev/stderr"
        failed = 1
        next
      }
      statements[owner] += $2
      if ($3 > 0) {
        covered[owner] += $2
      }
    }
    END {
      for (item = 1; item <= package_count; item++) {
        package = packages[item]
        if (statements[package] > 0) {
          printf "%s\t%.2f\n", package,
            100 * covered[package] / statements[package]
        }
      }
      exit failed
    }
  ' "$profile" >"$report" || {
    rm -f -- "$package_file"
    return 1
  }
  rm -f -- "$package_file"
  sort -o "$report" "$report"
}

floor_for() {
  local package=$1
  local configured floor

  floor=$default_floor
  while read -r configured value; do
    [[ -n "${configured:-}" ]] || continue
    if [[ "$configured" == "$package" ]]; then
      floor=$value
      break
    fi
  done <<<"$package_floors"
  printf '%s\n' "$floor"
}

enforce_report() {
  local actual configured floor package status=0
  local seen=$'\n'

  while IFS=$'\t' read -r package actual; do
    [[ -n "$package" ]] || continue
    floor=$(floor_for "$package")
    printf '%-64s %6.2f%% / %6.2f%%\n' "$package" "$actual" "$floor"
    awk -v actual="$actual" -v floor="$floor" \
      'BEGIN { exit !(actual + 0 >= floor + 0) }' || status=1
    seen+="$package"$'\n'
  done <"$1"

  while read -r configured floor; do
    [[ -n "${configured:-}" ]] || continue
    if [[ "$seen" != *$'\n'"$configured"$'\n'* ]]; then
      printf 'coverage policy names unknown package %s\n' "$configured" >&2
      status=1
    fi
  done <<<"$package_floors"
  return "$status"
}

run_check() {
  local failure_output package_file profile report
  local packages

  packages=$(go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' \
    ./... | sed '/^[[:space:]]*$/d') || {
    printf 'coverage package inventory failed\n' >&2
    return 1
  }
  if [[ -z "$packages" ]]; then
    printf 'No Go packages exist\n'
    return
  fi

  profile=$(mktemp "${TMPDIR:-/tmp}/celestia-coverage.XXXXXX")
  report=$(mktemp "${TMPDIR:-/tmp}/celestia-coverage-report.XXXXXX")
  package_file=$report.packages
  failure_output=$(mktemp "${TMPDIR:-/tmp}/celestia-coverage-failure.XXXXXX")
  trap 'rm -f -- "${profile:-}" "${report:-}" "${package_file:-}" "${failure_output:-}"' EXIT
  create_report "$profile" "$report" "$packages" "$failure_output"
  enforce_report "$report"
  rm -f -- "$profile" "$report" "$package_file" "$failure_output"
  trap - EXIT
}

if (($# != 1)); then
  usage
  exit 2
fi

load_policy
case "$1" in
verify)
  run_check
  ;;
*)
  usage
  exit 2
  ;;
esac
