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
root=${CELESTIA_VERIFICATION_ROOT:-$(cd -- "$script_dir/../../.." && pwd)}
work_dir=$(new_verification_work verification-action)
action_driver_pid=
trap 'cleanup_verification "$work_dir" "$action_driver_pid"' EXIT
trap '[[ $- != *e* ]] || printf "verification-action failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

real_go=$(command -v go)
bash "$root/.github/scripts/actioncheck_test.sh"
family_repo="$work_dir/action-families"
family_dir="$family_repo/families"
mkdir -p "$family_dir"
git -C "$family_repo" init -q
git -C "$family_repo" config core.autocrlf false
families='remote_release_test.sh
cache_test.sh
inventory_test.sh
permissions_test.sh'
while IFS= read -r family; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$family_dir/$family"
  chmod +x "$family_dir/$family"
done <<<"$families"
printf '%s\n' '#!/usr/bin/env bash' 'exit 9' \
  >"$family_dir/inventory_test.sh"
git -C "$family_repo" add -f families
while IFS= read -r family; do
  git -C "$family_repo" update-index --chmod=+x "families/$family"
done <<<"$families"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
descendant_pid=
terminate() {
  trap - TERM
  if [[ -n "$descendant_pid" ]]; then
    kill -TERM "$descendant_pid" 2>/dev/null || true
    wait "$descendant_pid" 2>/dev/null || true
  fi
  exit 143
}
trap terminate TERM
printf '%s\n' "$$" >"$CELESTIA_ACTION_FAMILY_PID"
sleep 60 &
descendant_pid=$!
printf '%s\n' "$descendant_pid" >"$CELESTIA_ACTION_DESCENDANT_PID"
kill -STOP "$descendant_pid"
wait "$descendant_pid"
EOF
chmod +x "$family_dir/remote_release_test.sh"
git -C "$family_repo" add families/remote_release_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh
mkdir -- "$work_dir/action-cancellation-temp"
CELESTIA_ACTION_DESCENDANT_PID="$work_dir/action-descendant.pid" \
  CELESTIA_ACTION_FAMILY_PID="$work_dir/action-family.pid" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  TMPDIR="$work_dir/action-cancellation-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >"$work_dir/action-cancellation-output" 2>&1 &
action_driver_pid=$!
for _ in {1..50}; do
  [[ -s "$work_dir/action-descendant.pid" ]] && break
  sleep 0.1
done
[[ -s "$work_dir/action-family.pid" &&
  -s "$work_dir/action-descendant.pid" ]] || {
  printf 'action cancellation fixture did not start\n' >&2
  return 1
}
action_family_pid=$(cat "$work_dir/action-family.pid")
action_descendant_pid=$(cat "$work_dir/action-descendant.pid")
kill -TERM "$action_driver_pid"
set +e
wait "$action_driver_pid" 2>/dev/null
status=$?
set -e
action_driver_pid=
if [[ "$status" -ne 143 ]]; then
  cat "$work_dir/action-cancellation-output" >&2
  printf 'action cancellation returned status %d, want 143\n' "$status" >&2
  return 1
fi
for pid in "$action_family_pid" "$action_descendant_pid"; do
  if verification_process_running "$pid"; then
    printf 'action cancellation retained process %s\n' "$pid" >&2
    kill "$pid" 2>/dev/null || true
    return 1
  fi
done
require_empty_verification_directory "$work_dir/action-cancellation-temp" \
  'action cancellation temporary'
mkdir -- "$work_dir/action-cleanup-failure-temp"
CELESTIA_ACTION_CLEANUP_FAILURE=1 \
  CELESTIA_ACTION_DESCENDANT_PID="$work_dir/action-failed-descendant.pid" \
  CELESTIA_ACTION_FAMILY_PID="$work_dir/action-failed-family.pid" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  TMPDIR="$work_dir/action-cleanup-failure-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >"$work_dir/action-cleanup-failure-output" 2>&1 &
action_driver_pid=$!
for _ in {1..50}; do
  [[ -s "$work_dir/action-failed-descendant.pid" ]] && break
  sleep 0.1
done
[[ -s "$work_dir/action-failed-family.pid" &&
  -s "$work_dir/action-failed-descendant.pid" ]] || {
  printf 'action cleanup failure fixture did not start\n' >&2
  return 1
}
action_family_pid=$(cat "$work_dir/action-failed-family.pid")
action_descendant_pid=$(cat "$work_dir/action-failed-descendant.pid")
kill -TERM "$action_driver_pid"
set +e
wait "$action_driver_pid" 2>/dev/null
status=$?
set -e
action_driver_pid=
if [[ "$status" -ne 1 ]]; then
  printf 'action cleanup failure returned status %d, want 1\n' \
    "$status" >&2
  return 1
fi
if ! grep -Fq 'cancellation cleanup failed' \
  "$work_dir/action-cleanup-failure-output"; then
  printf 'action cleanup failure lost its diagnostic\n' >&2
  return 1
fi
for pid in "$action_family_pid" "$action_descendant_pid"; do
  if verification_process_running "$pid"; then
    printf 'action cleanup failure retained process %s\n' "$pid" >&2
    kill "$pid" 2>/dev/null || true
    return 1
  fi
done
require_empty_verification_directory "$work_dir/action-cleanup-failure-temp" \
  'action cleanup failure temporary'
mkdir -- "$work_dir/action-pre-wait-temp"
CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  CELESTIA_ACTION_PREWAIT_CHECKPOINT_READY="$work_dir/action-pre-wait-ready" \
  CELESTIA_ACTION_PREWAIT_CHECKPOINT_RELEASE="$work_dir/action-pre-wait-release" \
  TMPDIR="$work_dir/action-pre-wait-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1 &
action_driver_pid=$!
for _ in {1..500}; do
  [[ -e "$work_dir/action-pre-wait-ready" ]] && break
  sleep 0.01
done
if [[ ! -e "$work_dir/action-pre-wait-ready" ]]; then
  printf 'action pre-wait checkpoint was not reached\n' >&2
  return 1
fi
kill -TERM "$action_driver_pid"
: >"$work_dir/action-pre-wait-release"
set +e
wait "$action_driver_pid" 2>/dev/null
status=$?
set -e
action_driver_pid=
if [[ "$status" -ne 143 ]]; then
  printf 'pre-wait action cancellation returned status %d, want 143\n' \
    "$status" >&2
  return 1
fi
require_empty_verification_directory "$work_dir/action-pre-wait-temp" \
  'action pre-wait temporary'
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
: >"$CELESTIA_ACTION_PRELAUNCH_FAMILY_MARKER"
EOF
chmod +x "$family_dir/remote_release_test.sh"
git -C "$family_repo" add families/remote_release_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh
mkdir -- "$work_dir/action-pre-launch-temp"
CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  CELESTIA_ACTION_LAUNCH_CHECKPOINT_READY="$work_dir/action-launch-ready" \
  CELESTIA_ACTION_LAUNCH_CHECKPOINT_RELEASE="$work_dir/action-launch-release" \
  CELESTIA_ACTION_MAIN_MARKER="$work_dir/action-main-started" \
  CELESTIA_ACTION_PRELAUNCH_FAMILY_MARKER="$work_dir/action-family-started" \
  TMPDIR="$work_dir/action-pre-launch-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1 &
action_driver_pid=$!
for _ in {1..500}; do
  [[ -e "$work_dir/action-launch-ready" ]] && break
  sleep 0.01
done
if [[ ! -e "$work_dir/action-launch-ready" ]]; then
  printf 'action launch checkpoint was not reached\n' >&2
  return 1
fi
kill -TERM "$action_driver_pid"
: >"$work_dir/action-launch-release"
set +e
wait "$action_driver_pid" 2>/dev/null
status=$?
set -e
action_driver_pid=
if [[ "$status" -ne 143 ]]; then
  printf 'pre-launch action cancellation returned status %d, want 143\n' \
    "$status" >&2
  return 1
fi
if [[ -e "$work_dir/action-main-started" ||
  -e "$work_dir/action-family-started" ]]; then
  printf 'pre-launch action cancellation started governed work\n' >&2
  return 1
fi
require_empty_verification_directory "$work_dir/action-pre-launch-temp" \
  'action pre-launch temporary'
mkdir -- "$work_dir/action-pre-release-temp"
CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  CELESTIA_ACTION_MAIN_MARKER="$work_dir/action-released-main" \
  CELESTIA_ACTION_PRELAUNCH_FAMILY_MARKER="$work_dir/action-released-family" \
  CELESTIA_ACTION_CANCEL_CHECKPOINT_READY="$work_dir/action-cancel-ready" \
  CELESTIA_ACTION_CANCEL_CHECKPOINT_RELEASE="$work_dir/action-cancel-release" \
  CELESTIA_ACTION_RELEASE_CHECKPOINT_READY="$work_dir/action-release-ready" \
  CELESTIA_ACTION_RELEASE_CHECKPOINT_RELEASE="$work_dir/action-release-release" \
  TMPDIR="$work_dir/action-pre-release-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1 &
action_driver_pid=$!
for _ in {1..500}; do
  [[ -e "$work_dir/action-release-ready" ]] && break
  sleep 0.01
done
if [[ ! -e "$work_dir/action-release-ready" ]]; then
  printf 'action release checkpoint was not reached\n' >&2
  return 1
fi
kill -TERM "$action_driver_pid"
: >"$work_dir/action-release-release"
for _ in {1..500}; do
  [[ -e "$work_dir/action-cancel-ready" ]] && break
  sleep 0.01
done
if [[ ! -e "$work_dir/action-cancel-ready" ]]; then
  printf 'action cancel checkpoint was not reached\n' >&2
  return 1
fi
: >"$work_dir/action-cancel-release"
set +e
wait "$action_driver_pid" 2>/dev/null
status=$?
set -e
action_driver_pid=
if [[ "$status" -ne 143 ]]; then
  printf 'pre-release action cancellation returned status %d, want 143\n' \
    "$status" >&2
  return 1
fi
if [[ -e "$work_dir/action-released-main" ||
  -e "$work_dir/action-released-family" ]]; then
  printf 'pre-release action cancellation started governed work\n' >&2
  return 1
fi
require_empty_verification_directory "$work_dir/action-pre-release-temp" \
  'action pre-release temporary'
mkdir -- "$work_dir/action-release-failure-temp"
set +e
CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  CELESTIA_ACTION_MAIN_MARKER="$work_dir/action-failed-release-main" \
  CELESTIA_ACTION_PRELAUNCH_FAMILY_MARKER="$work_dir/action-failed-release-family" \
  CELESTIA_ACTION_RELEASE_FAILURE=1 \
  TMPDIR="$work_dir/action-release-failure-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 1 ]]; then
  printf 'failed action release returned status %d, want 1\n' "$status" >&2
  return 1
fi
if [[ -e "$work_dir/action-failed-release-main" ||
  -e "$work_dir/action-failed-release-family" ]]; then
  printf 'failed action release started governed work\n' >&2
  return 1
fi
require_empty_verification_directory "$work_dir/action-release-failure-temp" \
  'action release failure temporary'
while IFS= read -r family; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$family_dir/$family"
  chmod +x "$family_dir/$family"
done <<<"$families"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
for status_path in "$TMPDIR"/celestia-action.*/main-status; do
  if [[ -e "$status_path" ]]; then
    exit 80
  fi
done
if (: <&8) 2>/dev/null; then
  exit 81
fi
if (: >&9) 2>/dev/null; then
  exit 82
fi
EOF
chmod +x "$family_dir/remote_release_test.sh"
git -C "$family_repo" add -f families
while IFS= read -r family; do
  git -C "$family_repo" update-index --chmod=+x "families/$family"
done <<<"$families"
mkdir -- "$work_dir/action-completion-temp"
CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  CELESTIA_ACTION_SIGNAL_MARKER="$work_dir/action-signal-attempted" \
  CELESTIA_ACTION_WAIT_CHECKPOINT_READY="$work_dir/action-wait-ready" \
  CELESTIA_ACTION_WAIT_CHECKPOINT_RELEASE="$work_dir/action-wait-release" \
  TMPDIR="$work_dir/action-completion-temp" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1 &
action_driver_pid=$!
for _ in {1..500}; do
  [[ -e "$work_dir/action-wait-ready" ]] && break
  sleep 0.01
done
if [[ ! -e "$work_dir/action-wait-ready" ]]; then
  printf 'action completion checkpoint was not reached\n' >&2
  return 1
fi
kill -TERM "$action_driver_pid"
: >"$work_dir/action-wait-release"
set +e
wait "$action_driver_pid" 2>/dev/null
status=$?
set -e
action_driver_pid=
if [[ "$status" -ne 0 ]]; then
  printf 'completed action driver returned status %d, want 0\n' \
    "$status" >&2
  return 1
fi
if [[ -e "$work_dir/action-signal-attempted" ]]; then
  printf 'completed action driver attempted to signal its former group\n' >&2
  return 1
fi
require_empty_verification_directory "$work_dir/action-completion-temp" \
  'action completion temporary'
snapshot_temp="$work_dir/action-snapshot-temp"
mkdir -p "$snapshot_temp"
printf 'tracked\n' >"$family_repo/missing-snapshot-input"
git -C "$family_repo" add missing-snapshot-input
rm -- "$family_repo/missing-snapshot-input"
set +e
output=$(TMPDIR="$snapshot_temp" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture 2>&1)
status=$?
set -e
git -C "$family_repo" rm --cached -q missing-snapshot-input
if [[ "$status" -eq 0 || "$output" != *missing-snapshot-input* ]]; then
  printf 'action snapshot failure lost its diagnostic:\n%s\n' "$output" >&2
  return 1
fi
require_empty_verification_directory "$snapshot_temp" \
  'action snapshot temporary'

master_marker="$work_dir/action-master-replacement-ran"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
cat >"families/cache_test.sh" <<'SCRIPT'
#!/usr/bin/env bash
: >"$CELESTIA_ACTION_MASTER_MARKER"
SCRIPT
chmod +x "families/cache_test.sh"
tar -cf ../snapshot.tar -C "$PWD" .
mkdir -p ../identities
git hash-object --no-filters -- "families/cache_test.sh" \
  >../identities/cache_test.sh
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/cache_test.sh"
chmod +x "$family_dir/remote_release_test.sh" "$family_dir/cache_test.sh"
git -C "$family_repo" add families/remote_release_test.sh \
  families/cache_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh families/cache_test.sh
set +e
output=$(CELESTIA_ACTION_MASTER_MARKER="$master_marker" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  2>&1)
status=$?
set -e
if [[ -e "$master_marker" ]]; then
  printf 'action driver trusted child-replaced master state\n' >&2
  return 1
fi
if [[ "$status" -eq 0 ]]; then
  printf 'action driver accepted child-replaced master state\n' >&2
  return 1
fi
if [[ "$output" != *"master snapshot identity differs"* ]]; then
  printf 'action master replacement lost its diagnostic:\n%s\n' \
    "$output" >&2
  return 1
fi
git -C "$family_repo" checkout-index --force -- \
  families/remote_release_test.sh families/cache_test.sh

watcher_bin="$work_dir/action-watcher-bin"
watcher_done="$work_dir/action-watcher-done"
watcher_marker="$work_dir/action-watcher-ran"
watcher_pid_file="$work_dir/action-watcher-pid"
watcher_ready="$work_dir/action-watcher-ready"
watcher_target="$work_dir/action-watcher-target"
mkdir -p "$watcher_bin"
cat >"$watcher_bin/git" <<'EOF'
#!/bin/sh
last=
for argument do
  last=$argument
done
case "$last" in
*/run.*/families/cache_test.sh)
  output=$("$CELESTIA_REAL_GIT" "$@") || exit $?
  printf '%s\n' "$last" >"$CELESTIA_ACTION_WATCHER_TARGET"
  : >"$CELESTIA_ACTION_WATCHER_READY"
  attempt=0
  while [ ! -e "$CELESTIA_ACTION_WATCHER_DONE" ] && \
    [ "$attempt" -lt 500 ]; do
    sleep 0.01
    attempt=$((attempt + 1))
  done
  [ -e "$CELESTIA_ACTION_WATCHER_DONE" ] || exit 98
  printf '%s\n' "$output"
  exit
  ;;
esac
exec "$CELESTIA_REAL_GIT" "$@"
EOF
chmod +x "$watcher_bin/git"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
(
  while [[ ! -e "$CELESTIA_ACTION_WATCHER_READY" ]]; do
    sleep 0.01
  done
  target=$(cat "$CELESTIA_ACTION_WATCHER_TARGET")
  cat >"$target" <<'SCRIPT'
#!/usr/bin/env bash
: >"$CELESTIA_ACTION_WATCHER_MARKER"
SCRIPT
  chmod +x "$target"
  : >"$CELESTIA_ACTION_WATCHER_DONE"
) >/dev/null 2>&1 &
watcher_pid=$!
printf '%s\n' "$watcher_pid" >"$CELESTIA_ACTION_WATCHER_PID_FILE"
disown "$watcher_pid"
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/cache_test.sh"
chmod +x "$family_dir/remote_release_test.sh" "$family_dir/cache_test.sh"
git -C "$family_repo" add families/remote_release_test.sh \
  families/cache_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh families/cache_test.sh
set +e
output=$(CELESTIA_ACTION_WATCHER_DONE="$watcher_done" \
  CELESTIA_ACTION_WATCHER_MARKER="$watcher_marker" \
  CELESTIA_ACTION_WATCHER_PID_FILE="$watcher_pid_file" \
  CELESTIA_ACTION_WATCHER_READY="$watcher_ready" \
  CELESTIA_ACTION_WATCHER_TARGET="$watcher_target" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  CELESTIA_REAL_GIT="$(command -v git)" \
  PATH="$watcher_bin:$PATH" \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture 2>&1)
status=$?
set -e
if [[ -e "$watcher_marker" ]]; then
  printf 'action driver executed a watcher-replaced family\n' >&2
  return 1
fi
if [[ "$status" -eq 0 ]]; then
  printf 'action driver accepted a retained family watcher\n' >&2
  return 1
fi
if [[ "$output" != *"retained descendant processes"* ]]; then
  printf 'action watcher rejection lost its diagnostic:\n%s\n' "$output" >&2
  return 1
fi
if [[ ! -s "$watcher_pid_file" ]]; then
  printf 'action watcher fixture did not start\n' >&2
  return 1
fi
watcher_pid=$(cat "$watcher_pid_file")
if verification_process_running "$watcher_pid"; then
  printf 'action driver retained family watcher %s\n' "$watcher_pid" >&2
  kill -KILL "$watcher_pid" 2>/dev/null || true
  return 1
fi
git -C "$family_repo" checkout-index --force -- \
  families/remote_release_test.sh families/cache_test.sh

nonzero_pid_file="$work_dir/action-nonzero-descendant-pid"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
sleep 60 >/dev/null 2>&1 &
descendant_pid=$!
printf '%s\n' "$descendant_pid" >"$CELESTIA_ACTION_NONZERO_PID_FILE"
disown "$descendant_pid"
exit 9
EOF
chmod +x "$family_dir/remote_release_test.sh"
git -C "$family_repo" add families/remote_release_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh
set +e
CELESTIA_ACTION_NONZERO_PID_FILE="$nonzero_pid_file" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 9 ]]; then
  printf 'action descendant cleanup replaced family status %d\n' \
    "$status" >&2
  return 1
fi
if [[ ! -s "$nonzero_pid_file" ]]; then
  printf 'action non-zero descendant fixture did not start\n' >&2
  return 1
fi
nonzero_pid=$(cat "$nonzero_pid_file")
if verification_process_running "$nonzero_pid"; then
  printf 'action non-zero family retained descendant %s\n' \
    "$nonzero_pid" >&2
  kill -KILL "$nonzero_pid" 2>/dev/null || true
  return 1
fi
git -C "$family_repo" checkout-index --force -- \
  families/remote_release_test.sh

race_marker="$work_dir/action-replacement-ran"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
cat >"$CELESTIA_ACTION_LATER_FAMILY" <<'SCRIPT'
#!/usr/bin/env bash
: >"$CELESTIA_ACTION_RACE_MARKER"
SCRIPT
chmod +x "$CELESTIA_ACTION_LATER_FAMILY"
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/cache_test.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/inventory_test.sh"
chmod +x "$family_dir/remote_release_test.sh" "$family_dir/cache_test.sh" \
  "$family_dir/inventory_test.sh"
git -C "$family_repo" add families/remote_release_test.sh \
  families/cache_test.sh families/inventory_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh families/cache_test.sh \
  families/inventory_test.sh
set +e
CELESTIA_ACTION_LATER_FAMILY="$family_dir/cache_test.sh" \
  CELESTIA_ACTION_RACE_MARKER="$race_marker" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1
status=$?
set -e
if [[ -e "$race_marker" ]]; then
  printf 'action driver executed a replaced family\n' >&2
  return 1
fi
if [[ "$status" -ne 0 ]]; then
  printf 'action driver rejected its replacement-safe snapshot\n' >&2
  return 1
fi
git -C "$family_repo" checkout-index --force -- \
  families/remote_release_test.sh families/cache_test.sh

race_marker="$work_dir/action-symlink-ran"
link_marker="$work_dir/action-symlink-created"
symlink_target="$work_dir/action-symlink-target.sh"
cat >"$symlink_target" <<'EOF'
#!/usr/bin/env bash
: >"$CELESTIA_ACTION_RACE_MARKER"
EOF
chmod +x "$symlink_target"
cat >"$family_dir/remote_release_test.sh" <<'EOF'
#!/usr/bin/env bash
rm -- "$CELESTIA_ACTION_LATER_FAMILY"
ln -s "$CELESTIA_ACTION_SYMLINK_TARGET" "$CELESTIA_ACTION_LATER_FAMILY"
: >"$CELESTIA_ACTION_LINK_MARKER"
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/cache_test.sh"
chmod +x "$family_dir/remote_release_test.sh" "$family_dir/cache_test.sh"
git -C "$family_repo" add families/remote_release_test.sh \
  families/cache_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh families/cache_test.sh
set +e
CELESTIA_ACTION_LATER_FAMILY="$family_dir/cache_test.sh" \
  CELESTIA_ACTION_LINK_MARKER="$link_marker" \
  CELESTIA_ACTION_RACE_MARKER="$race_marker" \
  CELESTIA_ACTION_SYMLINK_TARGET="$symlink_target" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1
status=$?
set -e
if [[ ! -e "$link_marker" ]]; then
  printf 'action symlink race did not execute\n' >&2
  return 1
fi
if [[ -e "$race_marker" ]]; then
  printf 'action driver executed a symlinked family\n' >&2
  return 1
fi
if [[ "$status" -ne 0 ]]; then
  printf 'action driver rejected its symlink-safe snapshot\n' >&2
  return 1
fi
git -C "$family_repo" checkout-index --force -- \
  families/remote_release_test.sh families/cache_test.sh

race_marker="$work_dir/action-working-change-ran"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/remote_release_test.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/cache_test.sh"
chmod +x "$family_dir/remote_release_test.sh"
git -C "$family_repo" add families/remote_release_test.sh \
  families/cache_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh families/cache_test.sh
cat >"$family_dir/cache_test.sh" <<'EOF'
#!/usr/bin/env bash
: >"$CELESTIA_ACTION_RACE_MARKER"
EOF
chmod +x "$family_dir/cache_test.sh"
CELESTIA_ACTION_RACE_MARKER="$race_marker" \
  CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture
if [[ ! -e "$race_marker" ]]; then
  printf 'action driver executed stale indexed family content\n' >&2
  return 1
fi
git -C "$family_repo" checkout-index --force -- families/cache_test.sh

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$family_dir/remote_release_test.sh"
chmod +x "$family_dir/remote_release_test.sh"
git -C "$family_repo" add families/remote_release_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/remote_release_test.sh
set +e
output=$(CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" 2>&1)
status=$?
set -e
if [[ "$status" -ne 2 ||
  "$output" != *"overrides require fixture mode"* ]]; then
  printf 'action test driver accepted an ambient family override:\n%s\n' \
    "$output" >&2
  return 1
fi
driver_temp="$work_dir/action-driver-temp"
mkdir -p "$driver_temp"
if require_empty_verification_directory "$work_dir/missing-driver-temp" \
  'action test driver temporary' \
  >/dev/null 2>&1; then
  printf 'action test driver accepted missing cleanup state\n' >&2
  return 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 9' \
  >"$family_dir/inventory_test.sh"
chmod +x "$family_dir/inventory_test.sh"
git -C "$family_repo" add families/inventory_test.sh
git -C "$family_repo" update-index --chmod=+x \
  families/inventory_test.sh
if TMPDIR="$driver_temp" CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'action test driver accepted a failing family\n' >&2
  return 1
fi
require_empty_verification_directory "$driver_temp" \
  'action test driver temporary'
repo_dir="$work_dir/repo"
mkdir -p "$repo_dir"
tar -cf - -C "$root" \
  .github/codeql .github/scripts .github/workflows \
  .github/.coverage .github/.currency .github/dependabot.yml \
  docs internal policies tools worker \
  .editorconfig .gitattributes .gitignore .golangci.yml \
  AGENTS.md Cargo.lock Cargo.toml deny.toml go.mod go.sum LICENSE README.md \
  rust-toolchain.toml | tar -xf - -C "$repo_dir"
git -C "$repo_dir" init -q
git -C "$repo_dir" config core.autocrlf false
git -C "$repo_dir" add -A
fake_bin="$work_dir/config-bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = actionlint ]; then
  : >"$CELESTIA_ACTIONLINT_MARKER"
  exit
fi
exec "$CELESTIA_REAL_GO" "$@"
EOF
chmod +x "$fake_bin/go"
cat >"$repo_dir/.github/workflows/alias-bomb.yml" <<'EOF'
name: Alias Bomb
permissions: read-all
on: push
jobs:
check:
  strategy:
    matrix:
      level0: &level0 [x, x, x, x, x, x, x, x, x, x]
      level1: &level1 [*level0, *level0, *level0, *level0, *level0, *level0, *level0, *level0, *level0, *level0]
      level2: &level2 [*level1, *level1, *level1, *level1, *level1, *level1, *level1, *level1, *level1, *level1]
      level3: &level3 [*level2, *level2, *level2, *level2, *level2, *level2, *level2, *level2, *level2, *level2]
      level4: &level4 [*level3, *level3, *level3, *level3, *level3, *level3, *level3, *level3, *level3, *level3]
      level5: &level5 [*level4, *level4, *level4, *level4, *level4, *level4, *level4, *level4, *level4, *level4]
      level6: &level6 [*level5, *level5, *level5, *level5, *level5, *level5, *level5, *level5, *level5, *level5]
      level7: [*level6, *level6, *level6, *level6, *level6, *level6, *level6, *level6, *level6, *level6]
  runs-on: ubuntu-latest
  steps: []
EOF
set +e
output=$(
  cd "$repo_dir" &&
    CELESTIA_ACTIONLINT_MARKER="$work_dir/actionlint-invoked" \
    CELESTIA_REAL_GO="$real_go" \
    PATH="$fake_bin:$PATH" \
    DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
rm -- "$repo_dir/.github/workflows/alias-bomb.yml"
[[ "$status" -ne 0 ]] || {
  printf 'devcheck accepted exponential YAML aliases\n' >&2
  return 1
}
if [[ -e "$work_dir/actionlint-invoked" ]] ||
  ! grep -Fq 'traversal budget' <<<"$output"; then
  printf 'devcheck reached actionlint before bounded workflow validation:\n%s\n' \
    "$output" >&2
  return 1
fi

)

main
