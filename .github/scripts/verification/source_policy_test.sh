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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$script_dir/../../.." && pwd)
script_dir_path="$script_dir/source_policy"
script_repo=$root
script_prefix=.github/scripts/verification/source_policy
scripts=(
  setup.sh
  architecture.sh
  manifests.sh
  source_bounds.sh
  go_execution.sh
  rust_cargo.sh
  suppressions.sh
  scanner_failure.sh
)

fixture_mode=${1:-}
case "$fixture_mode" in
"") ;;
--fixture)
  script_dir_path=${CELESTIA_SOURCE_POLICY_SCRIPT_DIR:?}
  script_repo=${CELESTIA_SOURCE_POLICY_SCRIPT_REPO:?}
  script_prefix=${CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX:?}
  ;;
*)
  printf 'Usage: source_policy_test.sh [--fixture]\n' >&2
  exit 2
  ;;
esac
if [[ "$fixture_mode" != --fixture ]] &&
  [[ -n "${CELESTIA_SOURCE_POLICY_SCRIPT_DIR+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SCRIPT_REPO+x}" ||
    -n "${CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX+x}" ]]; then
  printf 'source-policy script overrides require fixture mode\n' >&2
  exit 2
fi

# shellcheck source=.github/scripts/verification/fixture.sh
source "$script_dir/fixture.sh"

main() (
  local executed
  local mode
  local path
  local script
  local work_dir

  work_dir=$(new_verification_work verification-source-policy)
  executed="$work_dir/executed"
  trap 'cleanup_verification "$work_dir"' EXIT
  trap '[[ $- != *e* ]] || printf "verification-source-policy failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
  trap 'exit 1' HUP INT TERM

  for script in "${scripts[@]}"; do
    path="$script_dir_path/$script"
    mode=$(git -C "$script_repo" ls-files --stage -- "$script_prefix/$script")
    if [[ ! -f "$path" || "${mode%% *}" != 100755 ]]; then
      printf 'source-policy script is unavailable: %s\n' "$script" >&2
      return 1
    fi
    "$path" "$root" "$work_dir"
    printf '%s\n' "$script" >>"$executed"
  done
  if ! diff -u <(printf '%s\n' "${scripts[@]}") "$executed"; then
    printf 'source-policy scripts lacked ordered execution\n' >&2
    return 1
  fi
)

main "$@"
