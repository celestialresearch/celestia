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
work=$(mktemp -d "${TMPDIR:-/tmp}/testcheck-test.XXXXXX")

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

mkdir -p "$work/bin" "$work/package"
cat >"$work/bin/go" <<'EOF'
#!/usr/bin/env bash
if [[ "${SIGNAL_PARENT:-false}" == true ]]; then
  kill -TERM "${SIGNAL_TARGET_PID:?}"
  exit 0
fi
printf '%s\n' \
  '{"Action":"run","Package":"fixture.invalid/test","Test":"TestMustRun"}'
if [[ "${COMPLETE_TEST:-false}" == true ]]; then
  printf '%s\n' \
    '{"Action":"pass","Package":"fixture.invalid/test","Test":"TestMustRun"}'
fi
EOF
chmod +x "$work/bin/go"

cat >"$work/bin/testinventory" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == go ]]; then
  printf '%s\\n' 'fixture.invalid/test	TestMustRun'
else
  printf '%s\\t%s\\n' '$work/package' '$work/bin/rust-test'
fi
EOF
chmod +x "$work/bin/testinventory"

cat >"$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${CARGO_LOG:?}"
if [[ "$1" == test &&
  "$*" != *"--no-run"* &&
  "${FAIL_DOC_TEST:-false}" == true ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "$work/bin/cargo"

cat >"$work/bin/rust-test" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"--list"* ]]; then
  printf 'must_run: test\n'
elif [[ "${COMPLETE_TEST:-false}" != true ]]; then
  exit 1
elif [[ "$PWD" != "${EXPECTED_PACKAGE_ROOT:?}" ]]; then
  exit 1
else
  printf 'test result: ok. 1 passed; 0 failed; 0 ignored\n'
fi
EOF
chmod +x "$work/bin/rust-test"

set +e
PATH="$work/bin:$PATH" TESTINVENTORY_BIN="$work/bin/testinventory" \
  SIGNAL_PARENT=true \
  bash -c '
    export SIGNAL_TARGET_PID=$$
    exec bash "$@"
  ' _ "$root/.github/scripts/testcheck.sh" go quick --fixture >/dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 130 ]]; then
  printf 'Go completion check returned %d after termination\n' "$status" >&2
  exit 1
fi

if PATH="$work/bin:$PATH" TESTINVENTORY_BIN="$work/bin/testinventory" \
  bash "$root/.github/scripts/testcheck.sh" go quick --fixture \
  >/dev/null 2>&1; then
  printf 'Go completion check accepted a missing terminal outcome\n' >&2
  exit 1
fi
PATH="$work/bin:$PATH" TESTINVENTORY_BIN="$work/bin/testinventory" \
  COMPLETE_TEST=true \
  bash "$root/.github/scripts/testcheck.sh" go quick --fixture >/dev/null

set +e
output=$(
  CARGO_BIN="$work/bin/cargo" \
    bash "$root/.github/scripts/testcheck.sh" rust unused 2>&1
)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"CARGO_BIN is permitted only in fixture mode"* ]]; then
  printf 'Rust completion check accepted normal CARGO_BIN override:\n%s\n' \
    "$output" >&2
  exit 1
fi

if PATH="$work/bin:$PATH" CARGO_BIN="$work/bin/cargo" CARGO_LOG="$work/cargo.log" \
  TESTINVENTORY_BIN="$work/bin/testinventory" \
  bash "$root/.github/scripts/testcheck.sh" rust unused --fixture \
  >/dev/null 2>&1; then
  printf 'Rust completion check accepted a failed executable\n' >&2
  exit 1
fi
if PATH="$work/bin:$PATH" CARGO_BIN="$work/bin/cargo" CARGO_LOG="$work/cargo.log" \
  TESTINVENTORY_BIN="$work/bin/testinventory" \
  COMPLETE_TEST=true EXPECTED_PACKAGE_ROOT="$work/package" \
  FAIL_DOC_TEST=true \
  bash "$root/.github/scripts/testcheck.sh" rust unused --fixture \
  >/dev/null 2>&1; then
  printf 'Rust completion check accepted a failed documentation test\n' >&2
  exit 1
fi
PATH="$work/bin:$PATH" CARGO_BIN="$work/bin/cargo" CARGO_LOG="$work/cargo.log" \
  TESTINVENTORY_BIN="$work/bin/testinventory" \
  COMPLETE_TEST=true EXPECTED_PACKAGE_ROOT="$work/package" \
  bash "$root/.github/scripts/testcheck.sh" rust unused --fixture >/dev/null
if grep -Fv -- '--all-features' "$work/cargo.log" >/dev/null; then
  printf 'Rust completion check omitted all features:\n' >&2
  cat "$work/cargo.log" >&2
  exit 1
fi

verification_repo="$work/verification-repo"
verification_dir="$verification_repo/verification"
mkdir -p "$verification_dir"
git -C "$verification_repo" init -q
git -C "$verification_repo" config core.autocrlf false
families='lint_test.sh
action_test.sh
rust_config_test.sh
rust_artefact_test.sh
coverage_test.sh
source_policy_test.sh
licence_test.sh
release_artefact_test.sh'
while IFS= read -r family; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$verification_dir/$family"
  chmod +x "$verification_dir/$family"
done <<<"$families"
git -C "$verification_repo" add -f verification
while IFS= read -r family; do
  git -C "$verification_repo" update-index --chmod=+x \
    "verification/$family"
done <<<"$families"
CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture >/dev/null

set +e
output=$(
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" 2>&1
)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"overrides require fixture mode"* ]]; then
  printf 'verification driver accepted an ambient family override:\n%s\n' \
    "$output" >&2
  exit 1
fi

printf '%s\n' "$families" | sed '$d' >"$work/incomplete-execution"
if bash "$root/.github/scripts/testcheck.sh" verification \
  "$verification_dir" "$work/incomplete-execution" \
  "$verification_repo" verification >/dev/null 2>&1; then
  printf 'verification inventory accepted omitted execution\n' >&2
  exit 1
fi

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/unexpected_test.sh"
git -C "$verification_repo" add -f verification/unexpected_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/unexpected_test.sh
printf '%s\n' "$families" >"$work/complete-execution"
if bash "$root/.github/scripts/testcheck.sh" verification \
  "$verification_dir" "$work/complete-execution" \
  "$verification_repo" verification >/dev/null 2>&1; then
  printf 'verification inventory accepted an unexpected family\n' >&2
  exit 1
fi
git -C "$verification_repo" rm -q -f verification/unexpected_test.sh

rm -- "$verification_dir/action_test.sh"
if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'verification driver accepted a missing family\n' >&2
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$verification_dir/action_test.sh"
chmod +x "$verification_dir/action_test.sh"
git -C "$verification_repo" add verification/action_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/action_test.sh

git -C "$verification_repo" update-index --chmod=-x \
  verification/coverage_test.sh
if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'verification driver accepted a non-executable family\n' >&2
  exit 1
fi
git -C "$verification_repo" update-index --chmod=+x \
  verification/coverage_test.sh

printf '%s\n' '#!/usr/bin/env bash' 'exit 9' \
  >"$verification_dir/licence_test.sh"
chmod +x "$verification_dir/licence_test.sh"
git -C "$verification_repo" add verification/licence_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/licence_test.sh
if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'verification driver accepted a failing family\n' >&2
  exit 1
fi

action_repo="$work/action-repo"
action_dir="$action_repo/actioncheck"
mkdir -p "$action_dir"
git -C "$action_repo" init -q
git -C "$action_repo" config core.autocrlf false
action_families='remote_release_test.sh
cache_test.sh
inventory_test.sh
permissions_test.sh'
while IFS= read -r family; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$action_dir/$family"
  chmod +x "$action_dir/$family"
done <<<"$action_families"
git -C "$action_repo" add -f actioncheck
while IFS= read -r family; do
  git -C "$action_repo" update-index --chmod=+x "actioncheck/$family"
done <<<"$action_families"
printf '%s\n' "$action_families" >"$work/action-executed"
bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/action-executed" "$action_repo" actioncheck >/dev/null

printf '%s\n' "$action_families" | sed '$d' >"$work/action-incomplete"
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/action-incomplete" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted omitted execution\n' >&2
  exit 1
fi
printf '%s\n' "$action_families" | sed '1{h;d};2{p;g;}' \
  >"$work/action-reordered"
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/action-reordered" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted reordered execution\n' >&2
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$action_dir/unexpected_test.sh"
chmod +x "$action_dir/unexpected_test.sh"
git -C "$action_repo" add -f actioncheck/unexpected_test.sh
git -C "$action_repo" update-index --chmod=+x actioncheck/unexpected_test.sh
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/action-executed" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted an unexpected family\n' >&2
  exit 1
fi
git -C "$action_repo" rm -q -f actioncheck/unexpected_test.sh

rm -- "$action_dir/cache_test.sh"
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/action-executed" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted a missing family\n' >&2
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$action_dir/cache_test.sh"
chmod +x "$action_dir/cache_test.sh"
git -C "$action_repo" add actioncheck/cache_test.sh
git -C "$action_repo" update-index --chmod=+x actioncheck/cache_test.sh

git -C "$action_repo" update-index --chmod=-x \
  actioncheck/permissions_test.sh
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/action-executed" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted a non-executable family\n' >&2
source_policy_repo="$work/source-policy-repo"
source_policy_dir="$source_policy_repo/source-policy"
source_policy_log="$work/source-policy.log"
source_policy_temp="$work/source-policy-temp"
mkdir -p "$source_policy_dir"
mkdir -p "$source_policy_temp"
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
if find "$source_policy_temp" -mindepth 1 -print -quit | grep -q .; then
  printf 'source-policy driver retained failed fixture state\n' >&2
  exit 1
fi
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
