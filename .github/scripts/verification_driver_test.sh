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
initial_output="$work/initial-output"
run_initial_driver() {
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" --fixture
}
repository_temp_output="$work/repository-temp-output"
set +e
TMPDIR="$root/.github/scripts" run_initial_driver \
  >"$repository_temp_output" 2>&1
repository_temp_status=$?
set -e
if [[ "$repository_temp_status" -eq 0 ]] ||
  ! grep -Fq 'verification temporary root is inside the repository' \
    "$repository_temp_output"; then
  printf 'verification driver accepted a repository temporary root:\n' >&2
  cat "$repository_temp_output" >&2
  exit 1
fi
if find "$root/.github/scripts" -maxdepth 1 -type d \
  -name 'celestia-verification-driver.*' -print -quit | grep -q .; then
  printf 'verification temporary-root refusal retained repository state\n' >&2
  exit 1
fi
case "$(uname -s 2>/dev/null)" in
CYGWIN* | MINGW* | MSYS*)
  if ! run_initial_driver >"$initial_output" 2>&1; then
    printf 'verification driver rejected completed families:\n' >&2
    cat "$initial_output" >&2
    exit 1
  fi
  ;;
*)
  set -m
  run_initial_driver >"$initial_output" 2>&1 &
  initial_pid=$!
  for ((attempt = 0; attempt < 200; attempt++)); do
    verification_process_running "$initial_pid" || break
    sleep 0.05
  done
  if verification_process_running "$initial_pid"; then
    kill -KILL -- "-$initial_pid" 2>/dev/null || true
    wait "$initial_pid" 2>/dev/null || true
    set +m
    printf 'verification driver did not join completed families:\n' >&2
    cat "$initial_output" >&2
    exit 1
  fi
  set +e
  wait "$initial_pid"
  initial_status=$?
  set -e
  set +m
  if [[ "$initial_status" -ne 0 ]]; then
    printf 'verification driver rejected completed families:\n' >&2
    cat "$initial_output" >&2
    exit 1
  fi
  ;;
esac

cat >"$verification_dir/lint_test.sh" <<'EOF'
#!/usr/bin/env bash
trap ': >"$CELESTIA_TIMEOUT_SIGNAL_LEAK"' ALRM
trap '' TERM
printf '%s\n' "$$" >"$CELESTIA_TIMEOUT_FAMILY_PID"
sleep 4 &
printf '%s\n' "$!" >"$CELESTIA_TIMEOUT_DESCENDANT_PID"
wait
EOF
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/lint_test.sh
cat >"$verification_dir/action_test.sh" <<'EOF'
#!/usr/bin/env bash
printf reached >"$CELESTIA_TIMEOUT_LATER_FAMILY"
EOF
chmod +x "$verification_dir/action_test.sh"
git -C "$verification_repo" add verification/action_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/action_test.sh
timeout_temp="$work/family-timeout-temp"
timeout_output="$work/family-timeout-output"
mkdir "$timeout_temp"
set +e
CELESTIA_TIMEOUT_DESCENDANT_PID="$work/timeout-descendant.pid" \
  CELESTIA_TIMEOUT_FAMILY_PID="$work/timeout-family.pid" \
  CELESTIA_TIMEOUT_LATER_FAMILY="$work/timeout-later-family" \
  CELESTIA_TIMEOUT_SIGNAL_LEAK="$work/timeout-signal-leak" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS=1 \
  TMPDIR="$timeout_temp" \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >"$timeout_output" 2>&1
status=$?
set -e
if [[ "$status" -ne 124 ]] ||
  ! grep -Fq 'verification family timed out: lint_test.sh' \
    "$timeout_output"; then
  printf 'verification driver did not bound a sleeping family:\n' >&2
  cat "$timeout_output" >&2
  exit 1
fi
if [[ -e "$work/timeout-later-family" ]]; then
  printf 'verification driver continued after a family timeout\n' >&2
  exit 1
fi
if [[ -e "$work/timeout-signal-leak" ]]; then
  printf 'verification watchdog signalled the family process group\n' >&2
  exit 1
fi
for pid_file in "$work/timeout-family.pid" \
  "$work/timeout-descendant.pid"; do
  [[ -s "$pid_file" ]] || {
    printf 'verification timeout fixture omitted a process identity\n' >&2
    exit 1
  }
  if verification_process_running "$(cat "$pid_file")"; then
    printf 'verification timeout retained process %s\n' \
      "$(cat "$pid_file")" >&2
    exit 1
  fi
done
require_empty_verification_directory "$timeout_temp" \
  'verification timeout temporary'
for deadline_failure in marker notify; do
  failure_temp="$work/deadline-$deadline_failure-temp"
  failure_output="$work/deadline-$deadline_failure-output"
  failure_variable=CELESTIA_VERIFICATION_DEADLINE_MARKER_FAILURE
  failure_value=1
  if [[ "$deadline_failure" == notify ]]; then
    failure_variable=CELESTIA_VERIFICATION_DEADLINE_NOTIFY_FAILURE
    failure_value=once
  fi
  mkdir "$failure_temp"
  rm -f -- "$work/timeout-descendant.pid" "$work/timeout-family.pid" \
    "$work/timeout-later-family" "$work/timeout-signal-leak"
  set +e
  env "$failure_variable=$failure_value" \
    CELESTIA_TIMEOUT_DESCENDANT_PID="$work/timeout-descendant.pid" \
    CELESTIA_TIMEOUT_FAMILY_PID="$work/timeout-family.pid" \
    CELESTIA_TIMEOUT_LATER_FAMILY="$work/timeout-later-family" \
    CELESTIA_TIMEOUT_SIGNAL_LEAK="$work/timeout-signal-leak" \
    CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS=1 \
    TMPDIR="$failure_temp" \
    bash "$root/.github/scripts/verification_test.sh" --fixture \
    >"$failure_output" 2>&1
  status=$?
  set -e
  if [[ "$status" -ne 1 ]] ||
    ! grep -Fq 'verification family deadline mechanism failed: lint_test.sh' \
      "$failure_output"; then
    printf 'verification accepted a %s deadline failure:\n' \
      "$deadline_failure" >&2
    cat "$failure_output" >&2
    exit 1
  fi
  if [[ -e "$work/timeout-later-family" ]]; then
    printf 'verification continued after a %s deadline failure\n' \
      "$deadline_failure" >&2
    exit 1
  fi
  for pid_file in "$work/timeout-family.pid" \
    "$work/timeout-descendant.pid"; do
    if verification_process_running "$(cat "$pid_file")"; then
      printf 'verification %s deadline failure retained process %s\n' \
        "$deadline_failure" "$(cat "$pid_file")" >&2
      exit 1
    fi
  done
  require_empty_verification_directory "$failure_temp" \
    "verification $deadline_failure deadline failure temporary"
done
git -C "$verification_repo" checkout -- verification

descendant_pid_file="$work/success-descendant.pid"
descendant_later_marker="$work/success-descendant-later-ran"
cat >"$verification_dir/lint_test.sh" <<'EOF'
#!/usr/bin/env bash
snapshot=${BASH_SOURCE[0]%/*}
(
  attempt=0
  trap '' TERM
  while [[ -e "$snapshot/lint_test.sh" && "$attempt" -lt 400 ]]; do
    sleep 0.01
    attempt=$((attempt + 1))
  done
  [[ ! -e "$snapshot/lint_test.sh" ]] || exit 3
  attempt=0
  while [[ ! -e "$snapshot/action_test.sh" && "$attempt" -lt 400 ]]; do
    sleep 0.01
    attempt=$((attempt + 1))
  done
  [[ -e "$snapshot/action_test.sh" ]] || exit 4
  chmod u+w "$snapshot/action_test.sh"
  printf '%s\n' '#!/usr/bin/env bash' \
    ': >"$CELESTIA_DESCENDANT_LATER_MARKER"' \
    >"$snapshot/action_test.sh"
  chmod 500 "$snapshot/action_test.sh"
) &
printf '%s\n' "$!" >"$CELESTIA_DESCENDANT_PID_FILE"
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/action_test.sh"
chmod +x "$verification_dir/lint_test.sh" \
  "$verification_dir/action_test.sh"
git -C "$verification_repo" add verification/lint_test.sh \
  verification/action_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/lint_test.sh verification/action_test.sh
set +e
output=$(CELESTIA_DESCENDANT_PID_FILE="$descendant_pid_file" \
  CELESTIA_DESCENDANT_LATER_MARKER="$descendant_later_marker" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
status=$?
set -e
if [[ ! -s "$descendant_pid_file" ]]; then
  printf 'verification successful-family descendant did not start\n' >&2
  exit 1
fi
descendant_pid=$(cat "$descendant_pid_file")
if [[ -e "$descendant_later_marker" ]]; then
  printf 'verification driver executed a descendant-rewritten family\n' >&2
  exit 1
fi
if [[ "$status" -eq 0 ||
  "$output" != *"verification family left descendant processes: lint_test.sh"* ]]; then
  printf 'verification driver accepted a successful family descendant:\n%s\n' \
    "$output" >&2
  exit 1
fi
if verification_process_running "$descendant_pid"; then
  printf 'verification driver retained successful family descendant %s\n' \
    "$descendant_pid" >&2
  kill -KILL "$descendant_pid" 2>/dev/null || true
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/lint_test.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/action_test.sh"
chmod +x "$verification_dir/lint_test.sh" \
  "$verification_dir/action_test.sh"
git -C "$verification_repo" add verification/lint_test.sh \
  verification/action_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/lint_test.sh verification/action_test.sh

master_temp="$work/master-temp"
master_attack_marker="$work/master-attack-ran"
master_later_marker="$work/master-later-ran"
mkdir -- "$master_temp"
cat >"$verification_dir/lint_test.sh" <<'EOF'
#!/usr/bin/env bash
snapshot=${BASH_SOURCE[0]%/*}
for path in "$TMPDIR"/celestia-verification-driver.*/source.tar; do
  [[ -f "$path" ]] || continue
  chmod u+w -- "$path"
  chmod u+w -- "$snapshot/action_test.sh"
  printf '%s\n' '#!/usr/bin/env bash' \
    ': >"$CELESTIA_MASTER_LATER_MARKER"' \
    >"$snapshot/action_test.sh"
  chmod 500 -- "$snapshot/action_test.sh"
  tar -cf "$path" -C "$snapshot" .
  chmod 400 -- "$path"
  : >"$CELESTIA_MASTER_ATTACK_MARKER"
done
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/action_test.sh"
chmod +x "$verification_dir/lint_test.sh" \
  "$verification_dir/action_test.sh"
git -C "$verification_repo" add verification/lint_test.sh \
  verification/action_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/lint_test.sh verification/action_test.sh
set +e
output=$(TMPDIR="$master_temp" \
  CELESTIA_MASTER_ATTACK_MARKER="$master_attack_marker" \
  CELESTIA_MASTER_LATER_MARKER="$master_later_marker" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
status=$?
set -e
if [[ ! -e "$master_attack_marker" ]]; then
  printf 'verification master attack did not execute\n' >&2
  exit 1
fi
if [[ -e "$master_later_marker" ]]; then
  printf 'verification driver executed a child-rewritten master\n' >&2
  exit 1
fi
if [[ "$status" -eq 0 ||
  "$output" != *"verification master snapshot identity differs"* ]]; then
  printf 'verification driver accepted child-rewritten master state:\n%s\n' \
    "$output" >&2
  exit 1
fi
require_empty_verification_directory "$master_temp" \
  'verification master temporary'
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/lint_test.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"$verification_dir/action_test.sh"
chmod +x "$verification_dir/lint_test.sh" \
  "$verification_dir/action_test.sh"
git -C "$verification_repo" add verification/lint_test.sh \
  verification/action_test.sh
git -C "$verification_repo" update-index --chmod=+x \
  verification/lint_test.sh verification/action_test.sh

snapshot_checkpoint="$work/snapshot-checkpoint.sh"
cat >"$snapshot_checkpoint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$CELESTIA_VERIFICATION_SNAPSHOT_PATH" == action_test.sh ]] || exit 0
[[ ! -e "$CELESTIA_SNAPSHOT_RACE_MARKER" ]] || exit 0
: >"$CELESTIA_SNAPSHOT_RACE_MARKER"
case "$CELESTIA_SNAPSHOT_RACE_MODE" in
replace)
  printf '%s\n' '#!/usr/bin/env bash' 'exit 7' \
    >"$CELESTIA_SNAPSHOT_RACE_SOURCE"
  chmod +x "$CELESTIA_SNAPSHOT_RACE_SOURCE"
  ;;
symlink)
  rm -- "$CELESTIA_SNAPSHOT_RACE_SOURCE"
  mv -- "$CELESTIA_SNAPSHOT_RACE_LINK" \
    "$CELESTIA_SNAPSHOT_RACE_SOURCE"
  ;;
*) exit 2 ;;
esac
EOF
chmod +x "$snapshot_checkpoint"
for snapshot_race_mode in replace symlink; do
  snapshot_race_marker="$work/snapshot-$snapshot_race_mode-ran"
  snapshot_race_link="$verification_repo/snapshot-race-link"
  snapshot_race_target="$work/snapshot-$snapshot_race_mode-target.sh"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$snapshot_race_target"
  chmod +x "$snapshot_race_target"
  if [[ "$snapshot_race_mode" == symlink ]]; then
    create_verification_symlink "$verification_repo" snapshot-race-link \
      "$snapshot_race_target"
    git -C "$verification_repo" update-index --force-remove snapshot-race-link
  fi
  set +e
  output=$(CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT="$snapshot_checkpoint" \
    CELESTIA_SNAPSHOT_RACE_MARKER="$snapshot_race_marker" \
    CELESTIA_SNAPSHOT_RACE_MODE="$snapshot_race_mode" \
    CELESTIA_SNAPSHOT_RACE_LINK="$snapshot_race_link" \
    CELESTIA_SNAPSHOT_RACE_SOURCE="$verification_dir/action_test.sh" \
    CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
  status=$?
  set -e
  if [[ ! -e "$snapshot_race_marker" ]]; then
    printf 'verification %s snapshot race did not execute\n' \
      "$snapshot_race_mode" >&2
    exit 1
  fi
  if [[ "$status" -eq 0 || "$output" != *"action_test.sh"* ]]; then
    printf 'verification accepted a %s snapshot race:\n%s\n' \
      "$snapshot_race_mode" "$output" >&2
    exit 1
  fi
  rm -f -- "$verification_dir/action_test.sh"
  git -C "$verification_repo" checkout -- verification/action_test.sh
done

set +e
output=$(CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT="$work/missing-checkpoint" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ||
  "$output" != *"snapshot checkpoint is unavailable"* ]]; then
  printf 'verification accepted an unavailable snapshot checkpoint:\n%s\n' \
    "$output" >&2
  exit 1
fi

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

linked_source="$work/linked-source"
linked_repo="$work/linked-repo"
mv -- "$verification_dir" "$linked_source"
mkdir -- "$linked_repo"
git -C "$linked_repo" init -q
if ! create_verification_symlink "$linked_repo" verification \
  ../linked-source; then
  printf 'verification ancestor fixture could not create its link\n' >&2
  exit 1
fi
mv -- "$linked_repo/verification" "$verification_dir"
set +e
output=$(run_initial_driver 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ||
  "$output" != *"verification snapshot source is unavailable: lint_test.sh"* ]]; then
  printf 'verification driver accepted a linked source ancestor:\n%s\n' \
    "$output" >&2
  exit 1
fi
rm -- "$verification_dir"
mv -- "$linked_source" "$verification_dir"

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
printf '%s\n' "${BASH_SOURCE[0]%/*}" >"$CELESTIA_SNAPSHOT_PATH"
sleep 60 &
printf '%s\n' "$!" >"$CELESTIA_DESCENDANT_PID"
wait
EOF
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x verification/lint_test.sh
for driver_status_failure in '' 1 missing leading-zero out-of-range extra-line; do
  if [[ -n "$driver_status_failure" ]]; then
    cancellation_case=$driver_status_failure
    expected_status=1
  else
    cancellation_case=complete
    expected_status=143
  fi
  cancellation_temp="$work/cancellation-$cancellation_case-temp"
  cancellation_output="$work/cancellation-$cancellation_case-output"
  cancellation_snapshot="$work/cancellation-$cancellation_case-snapshot"
  rm -f -- "$work/family.pid" "$work/descendant.pid"
  mkdir "$cancellation_temp"
  TMPDIR="$cancellation_temp" \
    CELESTIA_DESCENDANT_PID="$work/descendant.pid" \
    CELESTIA_FAMILY_PID="$work/family.pid" \
    CELESTIA_SNAPSHOT_PATH="$cancellation_snapshot" \
    CELESTIA_VERIFICATION_DEADLINE_MARKER_FAILURE=1 \
    CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS=3 \
    CELESTIA_VERIFICATION_DRIVER_STATUS_FAILURE="$driver_status_failure" \
    bash "$root/.github/scripts/verification_test.sh" --fixture \
    >"$cancellation_output" 2>&1 &
  verification_pid=$!
  for _ in {1..300}; do
    [[ -s "$work/family.pid" && -s "$work/descendant.pid" ]] && break
    sleep 0.1
  done
  [[ -s "$work/family.pid" ]] || {
    printf 'verification cancellation fixture did not start:\n' >&2
    cat "$cancellation_output" >&2
    exit 1
  }
  [[ -s "$work/descendant.pid" ]] || {
    printf 'verification cancellation descendant did not start:\n' >&2
    cat "$cancellation_output" >&2
    exit 1
  }
  [[ -s "$cancellation_snapshot" ]] || {
    printf 'verification cancellation fixture omitted its snapshot path\n' >&2
    exit 1
  }
  family_pid=$(cat "$work/family.pid")
  descendant_pid=$(cat "$work/descendant.pid")
  snapshot_path=$(cat "$cancellation_snapshot")
  case "$snapshot_path" in
  "$cancellation_temp"/celestia-verification-driver.*/snapshot) ;;
  *)
    printf 'verification cancellation snapshot escaped owned state: %s\n' \
      "$snapshot_path" >&2
    exit 1
    ;;
  esac
  if find "$root/.github/scripts" -maxdepth 1 -type d \
    -name '.verification-family.*' -print -quit | grep -q .; then
    printf 'verification cancellation staged snapshot in the repository\n' >&2
    kill -TERM "$verification_pid" 2>/dev/null || true
    wait "$verification_pid" 2>/dev/null || true
    exit 1
  fi
  kill -TERM "$verification_pid"
  set +e
  wait "$verification_pid" 2>/dev/null
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    printf 'verification cancellation returned status %d, want %d\n' \
      "$status" "$expected_status" >&2
    cat "$cancellation_output" >&2
    exit 1
  fi
  if grep -Fq 'verification family deadline mechanism failed' \
    "$cancellation_output"; then
    printf 'verification cancellation activated a deadline failure\n' >&2
    exit 1
  fi
  if [[ "$driver_status_failure" == 1 ]] &&
    ! grep -Fq 'verification driver inner cleanup failed' \
      "$cancellation_output"; then
    printf 'verification cancellation omitted inner cleanup failure\n' >&2
    exit 1
  fi
  if [[ "$driver_status_failure" == missing ||
    "$driver_status_failure" == leading-zero ||
    "$driver_status_failure" == out-of-range ||
    "$driver_status_failure" == extra-line ]] &&
    ! grep -Fq 'verification driver status is invalid' \
      "$cancellation_output"; then
    printf 'verification cancellation accepted a malformed status\n' >&2
    exit 1
  fi
  require_empty_verification_directory "$cancellation_temp" \
    'verification cancellation temporary'
  if [[ -e "$snapshot_path" ]]; then
    printf 'verification cancellation retained its snapshot path\n' >&2
    exit 1
  fi
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
done

family_event_checkpoint="$work/family-event-checkpoint.sh"
cat >"$family_event_checkpoint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
kill -TERM "$CELESTIA_VERIFICATION_FAMILY_CONTROLLER_PID"
EOF
chmod +x "$family_event_checkpoint"
for family_event_order in cancellation-first timeout-first; do
  event_temp="$work/$family_event_order-temp"
  event_output="$work/$family_event_order-output"
  event_checkpoint_variable=CELESTIA_VERIFICATION_FAMILY_WAIT_CHECKPOINT
  expected_event_status=143
  expected_event_message=
  if [[ "$family_event_order" == timeout-first ]]; then
    event_checkpoint_variable=CELESTIA_VERIFICATION_FAMILY_DEADLINE_CHECKPOINT
    expected_event_status=124
    expected_event_message='verification family timed out: lint_test.sh'
  fi
  rm -f -- "$work/family.pid" "$work/descendant.pid"
  mkdir "$event_temp"
  set +e
  env "$event_checkpoint_variable=$family_event_checkpoint" \
    CELESTIA_DESCENDANT_PID="$work/descendant.pid" \
    CELESTIA_FAMILY_PID="$work/family.pid" \
    CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    CELESTIA_VERIFICATION_FAMILY_TIMEOUT_SECONDS=1 \
    TMPDIR="$event_temp" \
    bash "$root/.github/scripts/verification_test.sh" --fixture \
    >"$event_output" 2>&1
  status=$?
  set -e
  if [[ "$status" -ne "$expected_event_status" ]]; then
    printf 'verification misclassified %s arbitration:\n' \
      "$family_event_order" >&2
    cat "$event_output" >&2
    exit 1
  fi
  if [[ -n "$expected_event_message" ]] &&
    ! grep -Fq "$expected_event_message" "$event_output"; then
    printf 'verification omitted %s arbitration diagnostic:\n' \
      "$family_event_order" >&2
    cat "$event_output" >&2
    exit 1
  fi
  for pid_file in "$work/family.pid" "$work/descendant.pid"; do
    [[ -s "$pid_file" ]] || {
      printf 'verification %s fixture omitted a process identity\n' \
        "$family_event_order" >&2
      exit 1
    }
    if verification_process_running "$(cat "$pid_file")"; then
      printf 'verification %s retained process %s\n' \
        "$family_event_order" "$(cat "$pid_file")" >&2
      exit 1
    fi
  done
  require_empty_verification_directory "$event_temp" \
    "verification $family_event_order temporary"
done

spawn_checkpoint="$work/driver-spawn-checkpoint.sh"
cat >"$spawn_checkpoint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for _ in {1..300}; do
  [[ -s "$CELESTIA_FAMILY_PID" && -s "$CELESTIA_DESCENDANT_PID" ]] && break
  sleep 0.1
done
[[ -s "$CELESTIA_FAMILY_PID" && -s "$CELESTIA_DESCENDANT_PID" ]]
kill -TERM "$PPID"
EOF
chmod +x "$spawn_checkpoint"
spawn_temp="$work/spawn-cancellation-temp"
spawn_output="$work/spawn-cancellation-output"
mkdir "$spawn_temp"
rm -f -- "$work/family.pid" "$work/descendant.pid"
set +e
TMPDIR="$spawn_temp" \
  CELESTIA_DESCENDANT_PID="$work/descendant.pid" \
  CELESTIA_FAMILY_PID="$work/family.pid" \
  CELESTIA_VERIFICATION_DRIVER_SPAWN_CHECKPOINT="$spawn_checkpoint" \
  CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
  CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
  CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
  bash "$root/.github/scripts/verification_test.sh" --fixture \
  >"$spawn_output" 2>&1
status=$?
set -e
if [[ "$status" -ne 143 ]]; then
  printf 'verification spawn cancellation returned status %d, want 143\n' \
    "$status" >&2
  cat "$spawn_output" >&2
  exit 1
fi
family_pid=$(cat "$work/family.pid")
descendant_pid=$(cat "$work/descendant.pid")
for pid in "$family_pid" "$descendant_pid"; do
  if verification_process_running "$pid"; then
    printf 'verification spawn cancellation retained process %s\n' "$pid" >&2
    kill "$pid" 2>/dev/null || true
    exit 1
  fi
done
require_empty_verification_directory "$spawn_temp" \
  'verification spawn cancellation temporary'

wait_checkpoint="$work/wait-checkpoint.sh"
cat >"$wait_checkpoint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for _ in {1..300}; do
  [[ -s "$CELESTIA_FAMILY_PID" && -s "$CELESTIA_DESCENDANT_PID" ]] && break
  sleep 0.1
done
[[ -s "$CELESTIA_FAMILY_PID" && -s "$CELESTIA_DESCENDANT_PID" ]]
kill -TERM "$PPID"
EOF
chmod +x "$wait_checkpoint"
for wait_boundary in driver family; do
  wait_temp="$work/$wait_boundary-wait-temp"
  wait_output="$work/$wait_boundary-wait-output"
  wait_variable=CELESTIA_VERIFICATION_DRIVER_WAIT_CHECKPOINT
  expected_status=143
  if [[ "$wait_boundary" == family ]]; then
    wait_variable=CELESTIA_VERIFICATION_FAMILY_WAIT_CHECKPOINT
  fi
  mkdir "$wait_temp"
  rm -f -- "$work/family.pid" "$work/descendant.pid"
  set +e
  env "$wait_variable=$wait_checkpoint" \
    TMPDIR="$wait_temp" \
    CELESTIA_DESCENDANT_PID="$work/descendant.pid" \
    CELESTIA_FAMILY_PID="$work/family.pid" \
    CELESTIA_VERIFICATION_FAMILY_DIR="$verification_dir" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$verification_repo" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=verification \
    bash "$root/.github/scripts/verification_test.sh" --fixture \
    >"$wait_output" 2>&1
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    printf 'verification %s wait cancellation returned %d, want %d\n' \
      "$wait_boundary" "$status" "$expected_status" >&2
    cat "$wait_output" >&2
    exit 1
  fi
  family_pid=$(cat "$work/family.pid")
  descendant_pid=$(cat "$work/descendant.pid")
  for pid in "$family_pid" "$descendant_pid"; do
    if verification_process_running "$pid"; then
      printf 'verification %s wait retained process %s\n' \
        "$wait_boundary" "$pid" >&2
      kill "$pid" 2>/dev/null || true
      exit 1
    fi
  done
  require_empty_verification_directory "$wait_temp" \
    "verification $wait_boundary wait temporary"
done

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$verification_dir/lint_test.sh"
chmod +x "$verification_dir/lint_test.sh"
git -C "$verification_repo" add verification/lint_test.sh
git -C "$verification_repo" update-index --chmod=+x verification/lint_test.sh

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
