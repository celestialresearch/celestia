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
work=$(mktemp -d "${TMPDIR:-/tmp}/verification-driver.XXXXXX")
# shellcheck source=.github/scripts/verification/fixture.sh
source "$root/.github/scripts/verification/fixture.sh"

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

verification_repo="$work/repo"
verification_dir="$verification_repo/verification"
mkdir -p "$verification_dir"
git -C "$verification_repo" init -q
git -C "$verification_repo" config core.autocrlf false
families='lint_test.sh
action_test.sh
devcheck_config_test.sh
rust_config_test.sh
rust_integration_test.sh
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

cat >"$verification_dir/action_test.sh" <<'EOF'
#!/usr/bin/env bash
printf current >"$CELESTIA_CURRENT_FAMILY_MARKER"
EOF
chmod +x "$verification_dir/action_test.sh"
CELESTIA_CURRENT_FAMILY_MARKER="$work/current-family-ran" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture >/dev/null
if [[ ! -e "$work/current-family-ran" ]]; then
  printf 'verification driver ignored current family content\n' >&2
  exit 1
fi
git -C "$verification_repo" checkout -- verification/action_test.sh

cat >"$verification_dir/lint_test.sh" <<'EOF'
#!/usr/bin/env bash
cat >"$CELESTIA_REPLACED_FAMILY" <<'SCRIPT'
#!/usr/bin/env bash
printf replaced >"$CELESTIA_REPLACEMENT_MARKER"
SCRIPT
chmod +x "$CELESTIA_REPLACED_FAMILY"
EOF
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x verification/lint_test.sh
CELESTIA_REPLACED_FAMILY="$verification_dir/action_test.sh" \
  CELESTIA_REPLACEMENT_MARKER="$work/replacement-ran" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture >/dev/null
if [[ -e "$work/replacement-ran" ]]; then
  printf 'verification family replaced a later family\n' >&2
  exit 1
fi
git -C "$verification_repo" checkout -- verification

cat >"$verification_dir/lint_test.sh" <<'EOF'
#!/usr/bin/env bash
rm -- "$CELESTIA_REPLACED_FAMILY"
ln -s "$CELESTIA_REPLACEMENT_TARGET" "$CELESTIA_REPLACED_FAMILY"
EOF
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x verification/lint_test.sh
cat >"$work/replacement-target.sh" <<'EOF'
#!/usr/bin/env bash
printf symlinked >"$CELESTIA_REPLACEMENT_MARKER"
EOF
chmod +x "$work/replacement-target.sh"
CELESTIA_REPLACED_FAMILY="$verification_dir/action_test.sh" \
  CELESTIA_REPLACEMENT_MARKER="$work/symlink-ran" \
  CELESTIA_REPLACEMENT_TARGET="$work/replacement-target.sh" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture >/dev/null
if [[ -e "$work/symlink-ran" ]]; then
  printf 'verification family symlinked a later family\n' >&2
  exit 1
fi
rm -- "$verification_dir/action_test.sh"
git -C "$verification_repo" checkout -- verification

cat >"$verification_dir/lint_test.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$$" >"$CELESTIA_FAMILY_PID"
sleep 60 &
printf '%s\n' "$!" >"$CELESTIA_DESCENDANT_PID"
wait
EOF
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x verification/lint_test.sh
cancellation_temp="$work/cancellation-temp"
mkdir "$cancellation_temp"
TMPDIR="$cancellation_temp" \
  CELESTIA_DESCENDANT_PID="$work/descendant.pid" \
  CELESTIA_FAMILY_PID="$work/family.pid" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1 &
verification_pid=$!
for _ in {1..100}; do
  [[ -s "$work/family.pid" ]] && break
  sleep 0.1
done
[[ -s "$work/family.pid" ]] || {
  printf 'verification cancellation fixture did not start\n' >&2
  exit 1
}
[[ -s "$work/descendant.pid" ]] || {
  printf 'verification cancellation descendant did not start\n' >&2
  exit 1
}
family_pid=$(cat "$work/family.pid")
descendant_pid=$(cat "$work/descendant.pid")
kill -TERM "$verification_pid"
wait "$verification_pid" 2>/dev/null || true
require_empty_verification_directory "$cancellation_temp" \
  'verification cancellation temporary'
if find "$root/.github/scripts" -maxdepth 1 -type d \
  -name '.verification-family.*' -print -quit | grep -q .; then
  printf 'verification cancellation retained snapshot state\n' >&2
  exit 1
fi
for pid in "$family_pid" "$descendant_pid"; do
  if verification_process_running "$pid"; then
    printf 'verification cancellation retained process %s\n' "$pid" >&2
    kill "$pid" 2>/dev/null || true
    exit 1
  fi
done
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$verification_dir/lint_test.sh"
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x verification/lint_test.sh

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
