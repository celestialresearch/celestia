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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=.github/scripts/verification/fixture.sh
source "$script_dir/fixture.sh"

main() (
root=$(cd -- "$script_dir/../../.." && pwd)
work_dir=$(new_verification_work verification-rust-config)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-rust-config failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

set +e
output=$(
  cd "$root" &&
    DEVCHECK_PROFILE=invalid bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -eq 2 ]] || {
  printf 'devcheck accepted an unknown profile\n' >&2
  return 1
}
grep -Fq 'Unknown verification profile: invalid' <<<"$output" || {
  printf 'devcheck omitted the unknown-profile diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

set +e
output=$(
  cd "$root" &&
    GOFLAGS='-run=^$' DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'devcheck accepted an inherited Go test filter\n' >&2
  return 1
}
grep -Fq 'Uncontrolled Go test environment: GOFLAGS' <<<"$output" || {
  printf 'Go test filter rejection omitted the diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}
)

main
