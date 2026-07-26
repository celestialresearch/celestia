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
cache_root=${CELESTIA_CACHE_DIR:-.cache}

policy=.github/.coverage

usage() {
  printf 'Usage: %s verify|cached\n' "${0##*/}" >&2
}

load_policy() {
  local configured first second third extra

  default_floor=
  cache_max_age=
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
    cache-max-age-minutes)
      [[ -z "${third:-}" && -z "$cache_max_age" ]] || return 2
      cache_max_age=$second
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
  [[ "$cache_max_age" =~ ^[0-9]+$ ]] || {
    printf '%s: cache age must be a non-negative integer\n' "$policy" >&2
    return 2
  }
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

cache_key() (
  local file
  local inventory

  inventory=$(mktemp "${TMPDIR:-/tmp}/celestia-coverage.XXXXXX")
  trap 'rm -f -- "$inventory"' EXIT HUP INT TERM
  git ls-files -co --exclude-standard -z >"$inventory"

  {
    while IFS= read -r -d '' file; do
      [[ -f "$file" ]] || continue
      printf '%s\0' "$file"
      git hash-object -- "$file"
    done <"$inventory"
    go env GOVERSION GOOS GOARCH CGO_ENABLED CC CXX GOFLAGS
  } | git hash-object --stdin
)

create_report() {
  local profile=$1
  local report=$2
  local packages=$3
  local go_profile=$profile
  local package

  case "$(uname -s 2>/dev/null)" in
  CYGWIN*) go_profile=$(cygpath -w "$profile") ;;
  esac
  : >"$report"
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    go test -count=1 -covermode=atomic -coverprofile="$go_profile" \
      "$package" >/dev/null
    awk -v package="$package" '
      NR == 1 { next }
      {
        statements += $2
        if ($3 > 0) {
          covered += $2
        }
      }
      END {
        if (statements > 0) {
          printf "%s\t%.2f\n", package, 100 * covered / statements
        }
      }
    ' "$profile" >>"$report"
  done <<<"$packages"
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
  local cache_file key profile report temporary_cache
  local packages
  local status=0
  local use_cache=$1

  packages=$(go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' \
    ./... 2>/dev/null | sed '/^[[:space:]]*$/d') || return 1
  if [[ -z "$packages" ]]; then
    printf 'No Go packages exist\n'
    return
  fi

  key=$(cache_key)
  cache_file="$cache_root/coverage/$key.tsv"
  if [[ "$use_cache" == true && "$cache_max_age" -gt 0 &&
    -n "$(find "$cache_file" -mmin "-$cache_max_age" -print 2>/dev/null)" ]]; then
    enforce_report "$cache_file"
    return
  fi

  mkdir -p "$cache_root"
  profile=$(mktemp "$cache_root/coverage.XXXXXX")
  report=$(mktemp "$cache_root/coverage-report.XXXXXX")
  trap 'rm -f -- "${profile:-}" "${report:-}"' EXIT
  create_report "$profile" "$report" "$packages"
  enforce_report "$report" || status=1
  mkdir -p -- "$(dirname -- "$cache_file")"
  temporary_cache=$(mktemp "$(dirname -- "$cache_file")/.coverage.XXXXXX")
  if ! cp -- "$report" "$temporary_cache"; then
    rm -f -- "$temporary_cache" "$profile" "$report"
    trap - EXIT
    return 1
  fi
  if ! mv -f -- "$temporary_cache" "$cache_file"; then
    rm -f -- "$temporary_cache" "$profile" "$report"
    trap - EXIT
    return 1
  fi
  rm -f -- "$profile" "$report"
  trap - EXIT
  return "$status"
}

if (($# != 1)); then
  usage
  exit 2
fi

load_policy
case "$1" in
verify)
  run_check false
  ;;
cached)
  run_check true
  ;;
*)
  usage
  exit 2
  ;;
esac
