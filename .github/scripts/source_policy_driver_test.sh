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
work=$(mktemp -d "${TMPDIR:-/tmp}/source-policy-driver.XXXXXX")
# shellcheck source=.github/scripts/verification/fixture.sh
source "$root/.github/scripts/verification/fixture.sh"

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

source_policy_repo="$work/repo"
source_policy_dir="$source_policy_repo/source-policy"
source_policy_log="$work/source-policy.log"
source_policy_temp="$work/temp"
mkdir -p "$source_policy_dir" "$source_policy_temp"
if require_empty_verification_directory "$work/missing-temp" \
  'source-policy temporary' \
  >/dev/null 2>&1; then
  printf 'source-policy driver accepted missing cleanup state\n' >&2
  exit 1
fi
git -C "$source_policy_repo" init -q
git -C "$source_policy_repo" config core.autocrlf false
source_policy_scripts='setup.sh
architecture.sh
manifests.sh
source_bounds.sh
go_execution.sh
rust_cargo.sh
suppressions.sh
scanner_failure.sh'
while IFS= read -r script; do
  cat >"$source_policy_dir/$script" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$(basename -- "$0")" >>"$CELESTIA_SOURCE_POLICY_LOG"
EOF
  chmod +x "$source_policy_dir/$script"
done <<<"$source_policy_scripts"
git -C "$source_policy_repo" add -f source-policy
while IFS= read -r script; do
  git -C "$source_policy_repo" update-index --chmod=+x \
    "source-policy/$script"
done <<<"$source_policy_scripts"

CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null
if ! cmp -s <(printf '%s\n' "$source_policy_scripts") "$source_policy_log"; then
  printf 'source-policy driver reordered its scripts\n' >&2
  exit 1
fi

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$source_policy_dir/unexpected.sh"
chmod +x "$source_policy_dir/unexpected.sh"
git -C "$source_policy_repo" add -f source-policy/unexpected.sh
git -C "$source_policy_repo" update-index --chmod=+x \
  source-policy/unexpected.sh
if CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1; then
  printf 'source-policy driver accepted an unexpected script\n' >&2
  exit 1
fi
git -C "$source_policy_repo" rm -q -f source-policy/unexpected.sh

rm -- "$source_policy_dir/architecture.sh"
if CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1; then
  printf 'source-policy driver accepted a missing script\n' >&2
  exit 1
fi
git -C "$source_policy_repo" checkout -- source-policy/architecture.sh

mv -- "$source_policy_dir/architecture.sh" "$work/external-architecture.sh"
if ln -s "$work/external-architecture.sh" "$source_policy_dir/architecture.sh" &&
  [[ -L "$source_policy_dir/architecture.sh" ]]; then
  if CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
    CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
    CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
    CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
    bash "$root/.github/scripts/verification/source_policy_test.sh" \
      --fixture >/dev/null 2>&1; then
    printf 'source-policy driver accepted a symlinked script\n' >&2
    exit 1
  fi
  rm -- "$source_policy_dir/architecture.sh"
else
  rm -f -- "$source_policy_dir/architecture.sh"
fi
mv -- "$work/external-architecture.sh" "$source_policy_dir/architecture.sh"

git -C "$source_policy_repo" update-index --chmod=-x \
  source-policy/manifests.sh
if CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1; then
  printf 'source-policy driver accepted a non-executable script\n' >&2
  exit 1
fi
git -C "$source_policy_repo" update-index --chmod=+x \
  source-policy/manifests.sh

cat >"$source_policy_dir/go_execution.sh" <<'EOF'
#!/usr/bin/env bash
exit 9
EOF
chmod +x "$source_policy_dir/go_execution.sh"
git -C "$source_policy_repo" add source-policy/go_execution.sh
git -C "$source_policy_repo" update-index --chmod=+x \
  source-policy/go_execution.sh
rm -f -- "$source_policy_log"
set +e
CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
CELESTIA_VERIFICATION_TMPDIR="$source_policy_temp" \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 9 ]]; then
  printf 'source-policy driver changed script status 9 to %s\n' "$status" >&2
  exit 1
fi
require_empty_verification_directory "$source_policy_temp" \
  'source-policy temporary'
if ! cmp -s \
  <(printf '%s\n' setup.sh architecture.sh manifests.sh source_bounds.sh) \
  "$source_policy_log"; then
  printf 'source-policy driver continued after a failing script\n' >&2
  exit 1
fi

set +e
output=$(
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
    CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
    CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
    bash "$root/.github/scripts/verification/source_policy_test.sh" 2>&1
)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"overrides require fixture mode"* ]]; then
  printf 'source-policy driver accepted an ambient script override:\n%s\n' \
    "$output" >&2
  exit 1
fi
