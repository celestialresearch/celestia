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
CELESTIA_DESCENDANT_PID="$work/descendant.pid" \
  CELESTIA_FAMILY_PID="$work/family.pid" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1 &
verification_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
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
for pid in "$family_pid" "$descendant_pid"; do
  if kill -0 "$pid" 2>/dev/null; then
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
if CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'verification driver accepted a failing family\n' >&2
  exit 1
fi
