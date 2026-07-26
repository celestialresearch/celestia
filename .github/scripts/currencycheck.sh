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
exceptions=${CURRENCY_EXCEPTIONS_FILE:-"$root/.github/.currency"}

usage() {
  printf 'Usage: %s verify|currency|allows ECOSYSTEM COMPONENT VERSION\n' \
    "${0##*/}" >&2
}

records() {
  awk '
    /^[[:space:]]*(#|$)/ { next }
    { print }
  ' "$exceptions"
}

normalised_date() {
  local value=$1

  if date -u -d "$value" +%F 2>/dev/null; then
    return
  fi
  date -j -u -f '%Y-%m-%d' "$value" +%F 2>/dev/null
}

verify() {
  local component
  local ecosystem
  local expires
  local key
  local normalised
  local reason
  local seen=$'\n'
  local status=0
  local version

  [[ -f "$exceptions" ]] || {
    printf 'Missing currency exception file: %s\n' "$exceptions" >&2
    return 1
  }
  while IFS='|' read -r ecosystem component version expires reason extra; do
    if [[ -n "${extra:-}" || -z "$ecosystem" ||
      ! "$component" =~ ^[^[:space:]\|]+$ ||
      ! "$version" =~ ^[^[:space:]\|]+$ || -z "$expires" ||
      ! "$reason" =~ [^[:space:]] ]]; then
      printf 'Malformed currency exception: %s|%s|%s|%s|%s\n' \
        "$ecosystem" "$component" "$version" "$expires" "$reason" >&2
      status=1
      continue
    fi
    case "$ecosystem" in
    action | cargo | go | rust-tool | toolchain) ;;
    *)
      printf 'Unknown currency exception ecosystem: %s\n' "$ecosystem" >&2
      status=1
      ;;
    esac
    normalised=
    if [[ "$expires" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      normalised=$(normalised_date "$expires") || true
    fi
    if [[ "$normalised" != "$expires" ]]; then
      printf 'Invalid currency exception expiry: %s\n' "$expires" >&2
      status=1
    elif [[ "$expires" < "$(date -u +%F)" ]]; then
      printf 'Expired currency exception: %s %s\n' "$ecosystem" "$component" >&2
      status=1
    fi
    key="$ecosystem|$component|$version"
    if [[ "$seen" == *$'\n'"$key"$'\n'* ]]; then
      printf 'Duplicate currency exception: %s\n' "$key" >&2
      status=1
    fi
    seen+="$key"$'\n'
  done < <(records)
  return "$status"
}

allows() {
  local ecosystem=$1
  local component=$2
  local version=$3

  verify >/dev/null
  records |
    awk -F'|' -v ecosystem="$ecosystem" -v component="$component" \
      -v version="$version" '
        $1 == ecosystem && $2 == component && $3 == version { found = 1 }
        END { exit !found }
      '
}

accept_or_fail() {
  local ecosystem=$1
  local component=$2
  local current=$3
  local latest=$4

  if [[ "$current" == "$latest" ]]; then
    return
  fi
  if allows "$ecosystem" "$component" "$current"; then
    printf '%s %s retains %s by documented exception; latest is %s\n' \
      "$ecosystem" "$component" "$current" "$latest"
    return
  fi
  printf '%s %s uses %s; latest stable release is %s\n' \
    "$ecosystem" "$component" "$current" "$latest" >&2
  return 1
}

latest_crate() {
  local component=$1
  local cargo_bin=${CARGO_BIN:-cargo}
  local output

  if ! output=$("$cargo_bin" search "$component" --limit 1 2>&1); then
    printf 'Cargo search failed for %s: %s\n' "$component" "$output" >&2
    return 1
  fi
  sed -n "s/^${component} = \"\\([^\"]*\\)\".*/\\1/p" <<<"$output"
}

manifest_dependencies() {
  awk '
    FNR == 1 { active = 0; pending = "" }
    /^\[(workspace\.)?dependencies\]$/ { active = 1; next }
    active && /^\[/ { active = 0 }
    active && pending == "" &&
      /^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]*=/ {
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
  ' \
    "$root/Cargo.toml" \
    "$root/worker/qualification-fixtures/Cargo.toml" |
    sort -u
}

workflow_helpers() {
  sed -n \
    's/^[[:space:]]*\(cargo-[a-z0-9-]*\)@\([^[:space:]]*\).*$/\1|\2/p' \
    "$root"/.github/workflows/*.yml |
    sort -u
}

check_toolchain() {
  local current
  local latest
  local normalised
  local output
  local rustup_bin=${RUSTUP_BIN:-rustup}
  local rustup_status

  current=$(awk -F'"' '$1 ~ /^[[:space:]]*channel/ { print $2; exit }' \
    "$root/rust-toolchain.toml")
  set +e
  output=$("$rustup_bin" check 2>&1)
  rustup_status=$?
  set -e
  if ((rustup_status != 0 && rustup_status != 100)); then
    printf 'Rust toolchain currency check failed: %s\n' "$output" >&2
    return 1
  fi
  normalised=$(tr '[:upper:]' '[:lower:]' <<<"$output")
  latest=$(sed -n \
    's/^stable-.*update[[:space:]]*available[[:space:]]*:[[:space:]].*->[[:space:]]*\([0-9][0-9.]*\).*/\1/p' \
    <<<"$normalised")
  if [[ -z "$latest" ]]; then
    if grep -Eq '^stable-.*up[[:space:]]+to[[:space:]]+date[[:space:]]*:' \
      <<<"$normalised"; then
      latest=$current
    else
      printf 'Could not determine the latest stable Rust toolchain\n' >&2
      return 1
    fi
  fi
  accept_or_fail toolchain rust "$current" "$latest"
}

check_crates() {
  local component
  local current
  local latest
  local status=0

  while IFS='|' read -r component current; do
    [[ -n "$component" && -n "$current" ]] || continue
    latest=$(latest_crate "$component")
    if [[ -z "$latest" ]]; then
      printf 'Could not determine latest crate version: %s\n' \
        "$component" >&2
      status=1
      continue
    fi
    accept_or_fail cargo "$component" "$current" "$latest" || status=1
  done < <(manifest_dependencies)
  return "$status"
}

check_helpers() {
  local component
  local current
  local latest
  local status=0

  while IFS='|' read -r component current; do
    [[ -n "$component" && -n "$current" ]] || continue
    latest=$(latest_crate "$component")
    if [[ -z "$latest" ]]; then
      printf 'Could not determine latest Cargo helper version: %s\n' \
        "$component" >&2
      status=1
      continue
    fi
    accept_or_fail rust-tool "$component" "$current" "$latest" || status=1
  done < <(workflow_helpers)
  return "$status"
}

currency() {
  local status=0

  verify || status=1
  check_toolchain || status=1
  check_crates || status=1
  check_helpers || status=1
  return "$status"
}

case "${1:-}" in
verify)
  (($# == 1)) || {
    usage
    exit 2
  }
  verify
  ;;
currency)
  (($# == 1)) || {
    usage
    exit 2
  }
  currency
  ;;
allows)
  (($# == 4)) || {
    usage
    exit 2
  }
  allows "$2" "$3" "$4"
  ;;
*)
  usage
  exit 2
  ;;
esac
