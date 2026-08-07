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
max_profile_bytes=67108864

usage() {
  printf 'Usage: %s verify|enforce PROFILE\n' "${0##*/}" >&2
}

load_policy() {
  local configured configured_package configured_package_existing
  local configured_target fifth first fourth second third extra

  default_floor=
  package_floors=
  coverage_target=$(go env GOOS) || {
    printf '%s: unable to determine Go target\n' "$policy" >&2
    return 2
  }
  configured=$(go env GOARCH) || {
    printf '%s: unable to determine Go target\n' "$policy" >&2
    return 2
  }
  coverage_target+="/$configured"
  known_targets=$(go tool dist list) || {
    printf '%s: unable to list Go targets\n' "$policy" >&2
    return 2
  }
  while read -r first second third fourth fifth extra; do
    [[ -n "${first:-}" ]] || continue
    [[ "$first" != \#* ]] || continue
    case "$first" in
    default)
      [[ -n "${second:-}" && -z "${third:-}" && -z "${fourth:-}" &&
        -z "${fifth:-}" && -z "${extra:-}" && -z "$default_floor" ]] || {
        printf '%s: invalid default coverage policy\n' "$policy" >&2
        return 2
      }
      default_floor=$second
      ;;
    package)
      [[ -n "${second:-}" && -n "${third:-}" && -n "${fourth:-}" &&
        -n "${fifth:-}" && -z "${extra:-}" ]] || {
        printf '%s: invalid package coverage policy\n' "$policy" >&2
        return 2
      }
      configured_target=$second/$third
      configured_package=$fourth
      configured=$fifth
      target_is_known "$configured_target" || {
        printf '%s: unknown Go target %s\n' "$policy" "$configured_target" >&2
        return 2
      }
      while IFS=$'\t' read -r configured_target configured_package_existing _; do
        [[ -n "${configured_target:-}" ]] || continue
        if [[ "$configured_target" == "$second/$third" &&
          "$configured_package_existing" == "$configured_package" ]]; then
          printf '%s: duplicate coverage policy for %s on %s\n' \
            "$policy" "$configured_package" "$second/$third" >&2
          return 2
        fi
      done <<<"$package_floors"
      package_floors+="$second/$third"$'\t'"$configured_package"$'\t'"$configured"$'\n'
      ;;
    *)
      printf '%s: unknown coverage policy key %s\n' "$policy" "$first" >&2
      return 2
      ;;
    esac
  done <"$policy"

  validate_percentage "$default_floor" default
  while IFS=$'\t' read -r configured_target configured_package configured; do
    [[ -n "${configured_target:-}" ]] || continue
    validate_percentage "$configured" "$configured_package"
  done <<<"$package_floors"
}

target_is_known() {
  local target=$1

  [[ "$target" == */* && "$target" != */ && "$target" != /* ]] || return 1
  grep -Fqx -- "$target" <<<"$known_targets"
}

target_applies() {
  [[ "$1" == "$coverage_target" ]]
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
  local package_file=$3
  local failure_output=$4
  local go_profile=$profile

  case "$(uname -s 2>/dev/null)" in
  CYGWIN*) go_profile=$(cygpath -w "$profile") ;;
  esac
  : >"$report"
  if ! go test -p=1 -count=1 -covermode=atomic \
    -coverprofile="$go_profile" ./... 2>&1 |
    tail -c "$max_failure_output_bytes" >"$failure_output"; then
    printf 'coverage tests failed (last %s bytes):\n' \
      "$max_failure_output_bytes" >&2
    cat "$failure_output" >&2
    return 1
  fi
  report_profile "$profile" "$report" "$package_file"
}

report_profile() {
  local profile=$1
  local report=$2
  local package_file=$3

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
  ' "$profile" >"$report" || return 1
  sort -o "$report" "$report"
}

floor_for() {
  local package=$1
  local configured configured_package configured_target floor

  floor=$default_floor
  while IFS=$'\t' read -r configured_target configured_package configured; do
    [[ -n "${configured_target:-}" ]] || continue
    if [[ "$configured_target" == "$coverage_target" &&
      "$configured_package" == "$package" ]]; then
      printf '%s\n' "$configured"
      return
    fi
  done <<<"$package_floors"
  printf '%s\n' "$floor"
}

enforce_report() {
  local actual configured_package configured_target floor package package_file
  local status=0
  local seen=$'\n'

  package_file=$2

  while IFS=$'\t' read -r package actual; do
    [[ -n "$package" ]] || continue
    floor=$(floor_for "$package")
    printf '%-64s %6.2f%% / %6.2f%%\n' "$package" "$actual" "$floor"
    awk -v actual="$actual" -v floor="$floor" \
      'BEGIN { exit !(actual + 0 >= floor + 0) }' || status=1
    seen+="$package"$'\n'
  done <"$1"

  while IFS=$'\t' read -r configured_target configured_package floor; do
    [[ -n "${configured_target:-}" ]] || continue
    target_applies "$configured_target" || continue
    if ! grep -Fqx -- "$configured_package" "$package_file"; then
      printf 'coverage policy names unknown package %s\n' \
        "$configured_package" >&2
      status=1
    elif [[ "$seen" != *$'\n'"$configured_package"$'\n'* ]]; then
      printf 'coverage policy names package without coverage %s\n' \
        "$configured_package" >&2
      status=1
    fi
  done <<<"$package_floors"
  return "$status"
}

report_uncovered() {
  go tool cover -func="$1" | awk '
    $1 != "total:" && $NF != "100.0%" {
      if (reported < 200) print
      reported++
    }
    END {
      if (reported > 200) print "... uncovered function output truncated ..."
    }
  '
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
  printf '%s\n' "$packages" >"$package_file"
  create_report "$profile" "$report" "$package_file" "$failure_output"
  if ! enforce_report "$report" "$package_file"; then
    printf '\nNon-fully-covered functions (maximum 200):\n' >&2
    report_uncovered "$profile" >&2
    return 1
  fi
  rm -f -- "$profile" "$report" "$package_file" "$failure_output"
  trap - EXIT
}

enforce_profile() (
  local package_file
  local packages
  local profile=$1
  local profile_mode
  local report

  [[ -f "$profile" && ! -L "$profile" ]] || {
    printf 'coverage profile is unavailable\n' >&2
    return 1
  }
  [[ $(wc -c <"$profile") -le $max_profile_bytes ]] || {
    printf 'coverage profile exceeds the size limit\n' >&2
    return 1
  }
  IFS= read -r profile_mode <"$profile" || profile_mode=
  [[ "$profile_mode" == 'mode: atomic' ]] || {
    printf 'coverage profile is not atomic\n' >&2
    return 1
  }
  packages=$(go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' \
    ./... | sed '/^[[:space:]]*$/d') || {
    printf 'coverage package inventory failed\n' >&2
    return 1
  }
  [[ -n "$packages" ]] || {
    printf 'No Go packages exist\n'
    return
  }
  report=$(mktemp "${TMPDIR:-/tmp}/celestia-coverage-report.XXXXXX")
  package_file=$report.packages
  trap 'rm -f -- "$report" "$package_file"' EXIT
  printf '%s\n' "$packages" >"$package_file"
  report_profile "$profile" "$report" "$package_file"
  enforce_report "$report" "$package_file"
  rm -f -- "$report" "$package_file"
)

if (($# < 1 || $# > 2)); then
  usage
  exit 2
fi

load_policy
case "$1" in
verify)
  (($# == 1)) || { usage; exit 2; }
  run_check
  ;;
enforce)
  (($# == 2)) || { usage; exit 2; }
  enforce_profile "$2"
  ;;
*)
  usage
  exit 2
  ;;
esac
