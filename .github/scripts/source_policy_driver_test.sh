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
driver_pid=
descendant_pid=
setup_pid=
# shellcheck source=.github/scripts/verification/fixture.sh
source "$root/.github/scripts/verification/fixture.sh"

cleanup() {
  if [[ -n "$descendant_pid" ]]; then
    kill -KILL "$descendant_pid" 2>/dev/null || true
    wait "$descendant_pid" 2>/dev/null || true
  fi
  if [[ -n "$setup_pid" ]]; then
    kill -KILL -- "-$setup_pid" 2>/dev/null || true
  fi
  if [[ -n "$driver_pid" ]]; then
    terminate_child "$driver_pid"
  fi
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

snapshot_checkpoint="$work/snapshot-checkpoint.sh"
snapshot_fixture="$work/fixture.sh"
snapshot_target="$work/snapshot-target.sh"
cp -- "$root/.github/scripts/verification/fixture.sh" "$snapshot_fixture"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$snapshot_target"
cat >"$snapshot_checkpoint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
kind=$1
path=$2
[[ "$kind" == "$CELESTIA_SNAPSHOT_RACE_KIND" ]] || exit 0
[[ "$path" == "$CELESTIA_SNAPSHOT_RACE_SOURCE" ]] || exit 0
[[ ! -e "$CELESTIA_SNAPSHOT_RACE_MARKER" ]] || exit 0
case "$CELESTIA_SNAPSHOT_RACE_MODE" in
replace)
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$path"
  ;;
symlink)
  rm -- "$path"
  mv -- "$CELESTIA_SNAPSHOT_RACE_LINK" "$path"
  ;;
*) exit 2 ;;
esac
: >"$CELESTIA_SNAPSHOT_RACE_MARKER"
EOF
chmod +x "$snapshot_checkpoint" "$snapshot_target"
for snapshot_kind in fixture script; do
  for snapshot_mode in replace symlink; do
    snapshot_marker="$work/snapshot-$snapshot_kind-$snapshot_mode-ran"
    if [[ "$snapshot_kind" == fixture ]]; then
      snapshot_source=$snapshot_fixture
      snapshot_diagnostic='source-policy fixture changed during snapshot'
    else
      snapshot_source="$source_policy_dir/architecture.sh"
      snapshot_diagnostic='source-policy script changed during snapshot: architecture.sh'
    fi
    snapshot_link_repo="$work/snapshot-$snapshot_kind-$snapshot_mode-link"
    if [[ "$snapshot_mode" == symlink ]]; then
      mkdir -- "$snapshot_link_repo"
      git -C "$snapshot_link_repo" init -q
      create_verification_symlink "$snapshot_link_repo" link.sh \
        "$snapshot_target"
    fi
    set +e
    output=$(CELESTIA_SNAPSHOT_RACE_KIND="$snapshot_kind" \
      CELESTIA_SNAPSHOT_RACE_MARKER="$snapshot_marker" \
      CELESTIA_SNAPSHOT_RACE_MODE="$snapshot_mode" \
      CELESTIA_SNAPSHOT_RACE_SOURCE="$snapshot_source" \
      CELESTIA_SNAPSHOT_RACE_LINK="$snapshot_link_repo/link.sh" \
      CELESTIA_SOURCE_POLICY_FIXTURE_PATH="$snapshot_fixture" \
      CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
      CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
      CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
      CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
      CELESTIA_SOURCE_POLICY_SNAPSHOT_CHECKPOINT="$snapshot_checkpoint" \
      bash "$root/.github/scripts/verification/source_policy_test.sh" \
        --fixture 2>&1)
    status=$?
    set -e
    if [[ ! -e "$snapshot_marker" ]]; then
      printf 'source-policy %s %s snapshot race did not execute\n' \
        "$snapshot_kind" "$snapshot_mode" >&2
      exit 1
    fi
    if [[ "$status" -eq 0 || "$output" != *"$snapshot_diagnostic"* ]]; then
      printf 'source-policy accepted a %s %s snapshot race:\n%s\n' \
        "$snapshot_kind" "$snapshot_mode" "$output" >&2
      exit 1
    fi
    if [[ "$snapshot_kind" == fixture ]]; then
      rm -f -- "$snapshot_fixture"
      cp -- "$root/.github/scripts/verification/fixture.sh" "$snapshot_fixture"
    else
      rm -f -- "$source_policy_dir/architecture.sh"
      git -C "$source_policy_repo" checkout -- source-policy/architecture.sh
    fi
  done
done

double_rewrite_marker="$work/double-rewrite-ran"
cat >"$source_policy_dir/setup.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$(basename -- "$0")" >>"$CELESTIA_SOURCE_POLICY_LOG"
mkdir -p -- "$2/bindings"
cat >"$2/driver/source_policy/architecture.sh" <<'SCRIPT'
#!/usr/bin/env bash
: >"$CELESTIA_SOURCE_POLICY_DOUBLE_REWRITE_MARKER"
SCRIPT
cp -- "$2/driver/source_policy/architecture.sh" \
  "$2/bindings/architecture.sh"
chmod +x "$2/driver/source_policy/architecture.sh"
EOF
chmod +x "$source_policy_dir/setup.sh"
rm -f -- "$source_policy_log" "$double_rewrite_marker"
set +e
output=$(CELESTIA_SOURCE_POLICY_DOUBLE_REWRITE_MARKER="$double_rewrite_marker" \
  CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ||
  "$output" != *'source-policy script changed before execution: architecture.sh'* ||
  -e "$double_rewrite_marker" ]]; then
  printf 'source-policy driver accepted rewritten snapshot and binding:\n%s\n' \
    "$output" >&2
  exit 1
fi
git -C "$source_policy_repo" checkout -- source-policy/setup.sh

replacement_marker="$work/replacement-ran"
cat >"$source_policy_dir/setup.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$(basename -- "$0")" >>"$CELESTIA_SOURCE_POLICY_LOG"
cat >"$CELESTIA_SOURCE_POLICY_REPLACED" <<'SCRIPT'
#!/usr/bin/env bash
: >"$CELESTIA_SOURCE_POLICY_REPLACEMENT_MARKER"
SCRIPT
chmod +x "$CELESTIA_SOURCE_POLICY_REPLACED"
EOF
chmod +x "$source_policy_dir/setup.sh"
rm -f -- "$source_policy_log" "$replacement_marker"
CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_REPLACED="$source_policy_dir/architecture.sh" \
  CELESTIA_SOURCE_POLICY_REPLACEMENT_MARKER="$replacement_marker" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null
if [[ -e "$replacement_marker" ]] ||
  ! cmp -s <(printf '%s\n' "$source_policy_scripts") "$source_policy_log"; then
  printf 'source-policy driver executed a replaced script\n' >&2
  exit 1
fi
git -C "$source_policy_repo" checkout -- \
  source-policy/setup.sh source-policy/architecture.sh

cat >"$work/symlink-target.sh" <<'EOF'
#!/usr/bin/env bash
: >"$CELESTIA_SOURCE_POLICY_REPLACEMENT_MARKER"
EOF
chmod +x "$work/symlink-target.sh"
cat >"$source_policy_dir/setup.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$(basename -- "$0")" >>"$CELESTIA_SOURCE_POLICY_LOG"
rm -- "$CELESTIA_SOURCE_POLICY_REPLACED"
ln -s "$CELESTIA_SOURCE_POLICY_REPLACEMENT" \
  "$CELESTIA_SOURCE_POLICY_REPLACED"
EOF
chmod +x "$source_policy_dir/setup.sh"
rm -f -- "$source_policy_log" "$replacement_marker"
CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_REPLACED="$source_policy_dir/architecture.sh" \
  CELESTIA_SOURCE_POLICY_REPLACEMENT="$work/symlink-target.sh" \
  CELESTIA_SOURCE_POLICY_REPLACEMENT_MARKER="$replacement_marker" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null
if [[ -e "$replacement_marker" ]] ||
  ! cmp -s <(printf '%s\n' "$source_policy_scripts") "$source_policy_log"; then
  printf 'source-policy driver executed a symlinked replacement\n' >&2
  exit 1
fi
rm -- "$source_policy_dir/architecture.sh"
git -C "$source_policy_repo" checkout -- \
  source-policy/setup.sh source-policy/architecture.sh

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

create_verification_symlink "$source_policy_repo" \
  source-policy/hidden.sh setup.sh
git -C "$source_policy_repo" update-index --force-remove \
  source-policy/hidden.sh
if CELESTIA_SOURCE_POLICY_LOG="$source_policy_log" \
  CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
  CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
  CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1; then
  printf 'source-policy driver accepted an undeclared symlink script\n' >&2
  exit 1
fi
rm -- "$source_policy_dir/hidden.sh"

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

cat >"$source_policy_dir/setup.sh" <<'EOF'
#!/usr/bin/env bash
(
  trap '' TERM
  while :; do sleep 1; done
) &
printf '%d\n' "$!" >"$CELESTIA_DESCENDANT_PID"
EOF
chmod +x "$source_policy_dir/setup.sh"
git -C "$source_policy_repo" add source-policy/setup.sh
git -C "$source_policy_repo" update-index --chmod=+x source-policy/setup.sh
set +e
CELESTIA_DESCENDANT_PID="$work/descendant-pid" \
CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1
status=$?
set -e
if [[ ! -s "$work/descendant-pid" ]]; then
  printf 'source-policy descendant fixture did not start\n' >&2
  exit 1
fi
descendant_pid=$(cat "$work/descendant-pid")
if [[ "$status" -eq 0 ]]; then
  printf 'source-policy driver accepted a surviving descendant\n' >&2
  exit 1
fi
if verification_process_running "$descendant_pid"; then
  printf 'source-policy driver left a descendant alive after success\n' >&2
  exit 1
fi
descendant_pid=
git -C "$source_policy_repo" checkout -- source-policy/setup.sh

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

cat >"$source_policy_dir/setup.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%d\n' "$$" >"$CELESTIA_CANCELLATION_PROBE/setup-pid"
(
  trap '' TERM
  while :; do sleep 1; done
) &
printf '%d\n' "$!" >"$CELESTIA_CANCELLATION_PROBE/setup-child-pid"
while :; do sleep 1; done
EOF
chmod +x "$source_policy_dir/setup.sh"
git -C "$source_policy_repo" add source-policy/setup.sh
git -C "$source_policy_repo" update-index --chmod=+x source-policy/setup.sh
cancellation_probe="$work/cancellation"
mkdir -p "$cancellation_probe"
CELESTIA_SOURCE_POLICY_SCRIPT_DIR="$source_policy_dir" \
CELESTIA_SOURCE_POLICY_SCRIPT_REPO="$source_policy_repo" \
CELESTIA_SOURCE_POLICY_SCRIPT_PREFIX=source-policy \
CELESTIA_CANCELLATION_PROBE="$cancellation_probe" \
  bash "$root/.github/scripts/verification/source_policy_test.sh" \
    --fixture >/dev/null 2>&1 &
driver_pid=$!
attempt=0
while [[ (! -s "$cancellation_probe/setup-pid" ||
  ! -s "$cancellation_probe/setup-child-pid") && $attempt -lt 50 ]]; do
  verification_process_running "$driver_pid" || break
  sleep 0.1
  attempt=$((attempt + 1))
done
if [[ ! -s "$cancellation_probe/setup-pid" ||
  ! -s "$cancellation_probe/setup-child-pid" ]]; then
  printf 'source-policy cancellation fixture did not start\n' >&2
  exit 1
fi
setup_pid=$(cat "$cancellation_probe/setup-pid")
setup_child_pid=$(cat "$cancellation_probe/setup-child-pid")
kill -TERM "$driver_pid"
attempt=0
while verification_process_running "$driver_pid" && ((attempt < 50)); do
  sleep 0.1
  attempt=$((attempt + 1))
done
if verification_process_running "$driver_pid"; then
  printf 'source-policy driver did not stop after cancellation\n' >&2
  exit 1
fi
set +e
wait "$driver_pid"
status=$?
set -e
driver_pid=
if [[ "$status" -ne 143 ]]; then
  printf 'source-policy driver returned %d after cancellation\n' "$status" >&2
  exit 1
fi
if verification_process_running "$setup_pid"; then
  printf 'source-policy setup survived driver cancellation\n' >&2
  exit 1
fi
if verification_process_running "$setup_child_pid"; then
  printf 'source-policy setup descendant survived driver cancellation\n' >&2
  exit 1
fi
setup_pid=
