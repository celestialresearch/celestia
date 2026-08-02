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
family_dir="$root/.github/scripts/verification"
family_repo=$root
family_prefix=.github/scripts/verification
families=(
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
)

fixture_mode=${1:-}
case "$fixture_mode" in
"") ;;
--fixture)
  family_dir=${CELESTIA_VERIFICATION_FAMILY_DIR:?}
  family_repo=${CELESTIA_VERIFICATION_FAMILY_REPO:?}
  family_prefix=${CELESTIA_VERIFICATION_FAMILY_PREFIX:?}
  ;;
*)
  printf 'Usage: verification_test.sh [--fixture]\n' >&2
  exit 2
  ;;
esac
if [[ "$fixture_mode" != --fixture ]] &&
  [[ -n "${CELESTIA_VERIFICATION_FAMILY_DIR+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_REPO+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_PREFIX+x}" ]]; then
  printf 'verification family overrides require fixture mode\n' >&2
  exit 2
fi

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
terminate_family() {
  local pid=$1

  kill -TERM -- "-$pid" 2>/dev/null || true
  kill -KILL -- "-$pid" 2>/dev/null || true
}

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
finish_driver() {
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "${driver_pid:-}" ]]; then
    terminate_family "$driver_pid" 2>/dev/null || true
    wait "$driver_pid" 2>/dev/null || true
    driver_pid=
  fi
  exit "$status"
}

main() (
  local executed
  local family
  local mode
  local path

  executed=$(mktemp "${TMPDIR:-/tmp}/celestia-verification.XXXXXX")
  trap 'rm -f -- "$executed"' EXIT
  for family in "${families[@]}"; do
    path="$family_dir/$family"
    mode=$(git -C "$family_repo" ls-files --stage -- "$family_prefix/$family")
    if [[ -L "$path" || ! -f "$path" || "${mode%% *}" != 100755 ]]; then
      printf 'verification family is unavailable: %s\n' "$family" >&2
      return 1
    fi
    "$path"
    printf '%s\n' "$family" >>"$executed"
  done
  bash "$root/.github/scripts/testcheck.sh" verification "$family_dir" \
    "$executed" "$family_repo" "$family_prefix"
)

driver_pid=
trap 'finish_driver $?' EXIT
trap 'finish_driver 129' HUP
trap 'finish_driver 130' INT
trap 'finish_driver 143' TERM
set -m
main "$@" &
set +m
driver_pid=$!
set +e
wait "$driver_pid"
status=$?
set -e
driver_pid=
exit "$status"
