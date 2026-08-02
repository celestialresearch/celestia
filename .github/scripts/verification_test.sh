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
  rust_config_test.sh
  rust_artefact_test.sh
  coverage_test.sh
  source_policy_test.sh
  licence_test.sh
  release_artefact_test.sh
)

if [[ "${CELESTIA_VERIFICATION_FIXTURE:-false}" == true ]]; then
  family_dir=${CELESTIA_VERIFICATION_FAMILY_DIR:?}
  family_repo=${CELESTIA_VERIFICATION_FAMILY_REPO:?}
  family_prefix=${CELESTIA_VERIFICATION_FAMILY_PREFIX:?}
fi

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
    if [[ ! -f "$path" || "${mode%% *}" != 100755 ]]; then
      printf 'verification family is unavailable: %s\n' "$family" >&2
      return 1
    fi
    "$path"
    printf '%s\n' "$family" >>"$executed"
  done
  bash "$root/.github/scripts/testcheck.sh" verification "$family_dir" \
    "$executed" "$family_repo" "$family_prefix"
)

main "$@"
