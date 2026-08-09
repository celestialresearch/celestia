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

lockfile=${1:-}
if [[ -z "$lockfile" || ! -f "$lockfile" ]]; then
  printf 'Usage: %s CARGO_LOCK\n' "${0##*/}" >&2
  exit 2
fi

audit() {
  cargo audit --deny warnings --file "$lockfile"
}

output=$(mktemp)
trap 'rm -f -- "$output"' EXIT HUP INT TERM
if audit >"$output" 2>&1; then
  cat "$output"
  exit
fi

if ! grep -Fq 'error loading advisory database: git operation failed:' \
  "$output"; then
  cat "$output" >&2
  exit 1
fi

cargo_home=${CARGO_HOME:-${HOME:-}}
if [[ -z "$cargo_home" ]]; then
  printf 'Cannot determine Cargo home\n' >&2
  exit 1
fi
if [[ -z "${CARGO_HOME:-}" ]]; then
  cargo_home=$cargo_home/.cargo
fi
case "$cargo_home" in
"" | / | .) printf 'Unsafe Cargo home: %s\n' "$cargo_home" >&2; exit 1 ;;
esac
database=$cargo_home/advisory-db
case "$database" in
"$cargo_home"/advisory-db) rm -rf -- "$database" ;;
*) printf 'Unsafe advisory database path: %s\n' "$database" >&2; exit 1 ;;
esac

audit
