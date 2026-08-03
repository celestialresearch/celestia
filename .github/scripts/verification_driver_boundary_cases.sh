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

run_verification_driver_boundary_cases() {
  local root=$1
  local work=$2
  local verification_dir=$3
  local verification_repo=$4
  local families=$5
  local snapshot_checkpoint=$6

completion_checkpoint="$work/driver-completion-checkpoint.sh"
cat >"$completion_checkpoint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ! -e "$CELESTIA_COMPLETION_MARKER" ]]; then
  printf '%s\n' "$CELESTIA_VERIFICATION_COMPLETED_DRIVER_PID" \
    >"$CELESTIA_COMPLETION_MARKER"
  kill -TERM "$PPID"
fi
EOF
chmod +x "$completion_checkpoint"
completion_temp="$work/completion-boundary-temp"
mkdir "$completion_temp"
CELESTIA_COMPLETION_MARKER="$work/completion-boundary" \
  CELESTIA_VERIFICATION_DRIVER_COMPLETION_CHECKPOINT="$completion_checkpoint" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  TMPDIR="$completion_temp" \
  bash "$root/.github/scripts/verification_test.sh" --fixture >/dev/null
[[ -s "$work/completion-boundary" ]] || {
  printf 'verification completion boundary was not exercised\n' >&2
  exit 1
}
require_empty_verification_directory "$completion_temp" \
  'verification completion boundary temporary'

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

set +e
output=$(CELESTIA_VERIFICATION_DEADLINE_MARKER_FAILURE=1 \
  bash "$root/.github/scripts/verification_test.sh" 2>&1)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"overrides require fixture mode"* ]]; then
  printf 'verification driver accepted an ambient deadline failure:\n%s\n' \
    "$output" >&2
  exit 1
fi

set +e
output=$(CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS=1 \
  bash "$root/.github/scripts/verification_test.sh" 2>&1)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"overrides require fixture mode"* ]]; then
  printf 'verification driver accepted an ambient family timeout:\n%s\n' \
    "$output" >&2
  exit 1
fi

set +e
output=$(CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT="$snapshot_checkpoint" \
  bash "$root/.github/scripts/verification_test.sh" 2>&1)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"overrides require fixture mode"* ]]; then
  printf 'verification driver accepted an ambient snapshot checkpoint:\n%s\n' \
    "$output" >&2
  exit 1
fi

set +e
output=$(
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    CELESTIA_VERIFICATION_DRIVER_STATUS_FAILURE=invalid \
    bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1
)
status=$?
set -e
if [[ "$status" -ne 2 ]] ||
  [[ "$output" != *"driver status fixture is invalid"* ]]; then
  printf 'verification driver accepted an invalid status fixture:\n%s\n' \
    "$output" >&2
  exit 1
fi

for invalid_timeout in 0 invalid 3601; do
  set +e
  output=$(CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS="$invalid_timeout" \
    bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
  status=$?
  set -e
  if [[ "$status" -ne 2 ]] ||
    [[ "$output" != *"family timeout fixture is invalid"* ]]; then
    printf 'verification driver accepted family timeout %s:\n%s\n' \
      "$invalid_timeout" "$output" >&2
    exit 1
  fi
done

for failure_fixture in \
  CELESTIA_VERIFICATION_DEADLINE_MARKER_FAILURE=invalid \
  CELESTIA_VERIFICATION_DEADLINE_NOTIFY_FAILURE=invalid; do
  set +e
  output=$(env "$failure_fixture" \
    CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
  status=$?
  set -e
  if [[ "$status" -ne 2 ]] ||
    [[ "$output" != *"deadline failure fixture is invalid"* ]]; then
    printf 'verification driver accepted failure fixture %s:\n%s\n' \
      "$failure_fixture" "$output" >&2
    exit 1
  fi
done

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

create_verification_symlink "$verification_repo" \
  verification/hidden_test.sh lint_test.sh
if bash "$root/.github/scripts/testcheck.sh" verification \
  "$verification_dir" "$work/complete-execution" \
  "$verification_repo" verification >/dev/null 2>&1; then
  printf 'verification inventory accepted an undeclared symlink family\n' >&2
  exit 1
fi
rm -- "$verification_dir/hidden_test.sh"
git -C "$verification_repo" update-index --force-remove \
  verification/hidden_test.sh

rm -- "$verification_dir/devcheck_config_test.sh"
if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'verification driver accepted a missing family\n' >&2
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/devcheck_config_test.sh"
chmod +x "$verification_dir/devcheck_config_test.sh"
git -C "$verification_repo" add verification/devcheck_config_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/devcheck_config_test.sh

mv -- "$verification_dir/devcheck_config_test.sh" \
  "$work/external-devcheck-config.sh"
if ln -s "$work/external-devcheck-config.sh" \
  "$verification_dir/devcheck_config_test.sh" &&
  [[ -L "$verification_dir/devcheck_config_test.sh" ]]; then
  if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" --fixture \
    >/dev/null 2>&1; then
    printf 'verification driver accepted a symlinked family\n' >&2
    exit 1
  fi
  rm -- "$verification_dir/devcheck_config_test.sh"
else
  rm -f -- "$verification_dir/devcheck_config_test.sh"
fi
mv -- "$work/external-devcheck-config.sh" \
  "$verification_dir/devcheck_config_test.sh"

git -C "$verification_repo" update-index --chmod=-x \
  verification/rust_integration_test.sh
if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'verification driver accepted a non-executable family\n' >&2
  exit 1
fi
git -C "$verification_repo" update-index --chmod=+x \
  verification/rust_integration_test.sh

chmod 644 -- "$verification_dir/rust_integration_test.sh"
if [[ ! -x "$verification_dir/rust_integration_test.sh" ]]; then
  set +e
  output=$(CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
  status=$?
  set -e
  if [[ "$status" -eq 0 ||
    "$output" != *"verification snapshot source mode differs: rust_integration_test.sh"* ]]; then
    printf 'verification driver accepted working-tree mode drift:\n%s\n' \
      "$output" >&2
    exit 1
  fi
fi
chmod +x -- "$verification_dir/rust_integration_test.sh"

printf '%s\n' '#!/usr/bin/env bash' 'exit 9' \
  >"$verification_dir/rust_config_test.sh"
chmod +x "$verification_dir/rust_config_test.sh"
git -C "$verification_repo" add verification/rust_config_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/rust_config_test.sh
cat >"$verification_dir/rust_integration_test.sh" <<'EOF'
#!/usr/bin/env bash
printf started >"$CELESTIA_LATER_FAMILY"
EOF
chmod +x "$verification_dir/rust_integration_test.sh"
git -C "$verification_repo" add verification/rust_integration_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/rust_integration_test.sh
driver_temp="$work/driver-temp"
mkdir "$driver_temp"
set +e
CELESTIA_LATER_FAMILY="$work/later-family" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  TMPDIR="$driver_temp" \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 9 ]]; then
  printf 'verification driver returned %d after family failure\n' "$status" >&2
  exit 1
fi
if [[ -e "$work/later-family" ]]; then
  printf 'verification driver continued after family failure\n' >&2
  exit 1
fi
if ! retained_state=$(find "$driver_temp" -mindepth 1 -print -quit); then
  printf 'verification driver failure state is uninspectable\n' >&2
  exit 1
fi
if [[ -n "$retained_state" ]]; then
  printf 'verification driver retained failure state\n' >&2
  exit 1
fi
}
