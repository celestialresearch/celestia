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

main() (
root=$1
work_dir=$2
output=
status=0
architecture_dir="$work_dir/architecture-repo"
mkdir -p "$architecture_dir"
git -C "$root" archive HEAD | tar -xf - -C "$architecture_dir"
cp "$root/.golangci.yml" "$architecture_dir/.golangci.yml"
cp "$root/.github/scripts/depguardcheck.sh" \
  "$root/.github/scripts/policycheck.sh" \
  "$architecture_dir/.github/scripts/"
git -C "$architecture_dir" init -q
git -C "$architecture_dir" add .
(
  cd "$architecture_dir"
  bash .github/scripts/policycheck.sh architecture
) || {
  printf 'policy check rejected the governed architecture\n' >&2
  return 1
}
for variable in GOFLAGS GOENV; do
  set +e
  if [[ "$variable" == GOFLAGS ]]; then
    output=$(cd "$architecture_dir" &&
      GOFLAGS='-overlay=attacker.json' \
        bash .github/scripts/policycheck.sh architecture 2>&1)
  else
    output=$(cd "$architecture_dir" &&
      GOENV='attacker.env' \
        bash .github/scripts/policycheck.sh architecture 2>&1)
  fi
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted uncontrolled %s\n' "$variable" >&2
    return 1
  }
  grep -Fq "Uncontrolled Go policy environment: $variable" <<<"$output" || {
    printf 'policy check did not own the %s rejection:\n%s\n' \
      "$variable" "$output" >&2
    return 1
  }
done
set +e
CELESTIA_DEPGUARD_BOUNDED=1 CELESTIA_DEPGUARD_DEADLINE_FIXTURE=1 \
  bash "$architecture_dir/.github/scripts/depguardcheck.sh"
status=$?
set -e
[[ "$status" -eq 124 ]] || {
  printf 'depguard deadline fixture returned %s, expected 124\n' "$status" >&2
  return 1
}
depguard_cancel_dir="$work_dir/depguard-cancel"
mkdir -p "$depguard_cancel_dir"
TMPDIR="$depguard_cancel_dir" CELESTIA_DEPGUARD_DEADLINE_FIXTURE=1 \
  bash "$architecture_dir/.github/scripts/depguardcheck.sh" &
depguard_wrapper=$!
depguard_deadline_root=
for _ in 1 2 3 4 5; do
  for candidate in "$depguard_cancel_dir"/celestia-depguard-deadline.*; do
    if [[ -f "$candidate/child.pid" && -f "$candidate/watchdog.pid" ]]; then
      depguard_deadline_root=$candidate
      break 2
    fi
  done
  sleep 1
done
[[ -n "$depguard_deadline_root" ]] || {
  kill -TERM "$depguard_wrapper" 2>/dev/null || true
  wait "$depguard_wrapper" 2>/dev/null || true
  printf 'depguard cancellation fixture did not publish owned processes\n' >&2
  return 1
}
depguard_child=$(cat "$depguard_deadline_root/child.pid")
depguard_watchdog=$(cat "$depguard_deadline_root/watchdog.pid")
kill -TERM "$depguard_wrapper"
set +e
wait "$depguard_wrapper"
status=$?
set -e
[[ "$status" -eq 143 ]] || {
  printf 'cancelled depguard wrapper returned %s, expected 143\n' "$status" >&2
  return 1
}
for pid in "$depguard_child" "$depguard_watchdog"; do
  if kill -0 "$pid" 2>/dev/null; then
    printf 'cancelled depguard wrapper left process %s alive\n' "$pid" >&2
    return 1
  fi
done
[[ ! -e "$depguard_deadline_root" ]] || {
  printf 'cancelled depguard wrapper retained deadline state\n' >&2
  return 1
}
if ! command -v taskkill.exe >/dev/null 2>&1; then
  depguard_descendants="$work_dir/depguard-descendants"
  status=0
  CELESTIA_DEPGUARD_BOUNDED=1 CELESTIA_DEPGUARD_DEADLINE_FIXTURE=1 \
    CELESTIA_DEPGUARD_DESCENDANT_FILE="$depguard_descendants" \
    bash "$architecture_dir/.github/scripts/depguardcheck.sh" >/dev/null 2>&1 || status=$?
  [[ "$status" -eq 124 ]] || {
    printf 'depguard descendant fixture returned %s, expected 124\n' "$status" >&2
    return 1
  }
  while IFS= read -r pid; do
    if kill -0 "$pid" 2>/dev/null; then
      printf 'depguard deadline left descendant %s alive\n' "$pid" >&2
      return 1
    fi
  done <"$depguard_descendants"
fi
mkdir -p "$architecture_dir/worker/rogue"
printf 'package rogue\n' >"$architecture_dir/worker/rogue/main.go"
git -C "$architecture_dir" add worker/rogue/main.go
set +e
output=$(cd "$architecture_dir" &&
  bash .github/scripts/policycheck.sh architecture 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted an undeclared worker package\n' >&2
  return 1
}
grep -Fq 'worker/rogue/main.go: Go package is not declared' <<<"$output" || {
  printf 'policy output omitted the architecture diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}
git -C "$architecture_dir" rm -q --cached worker/rogue/main.go
rm -f -- "$architecture_dir/worker/rogue/main.go"
rmdir "$architecture_dir/worker/rogue"
printf '\nvar verificationAttemptDrift = 1\n' \
  >>"$architecture_dir/internal/operation/urlreference/attempt/contract.go"
set +e
output=$(cd "$architecture_dir" &&
  bash .github/scripts/policycheck.sh architecture 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted attempt declaration drift\n' >&2
  return 1
}
grep -Fq 'internal/operation/urlreference/attempt: source inventory differs:' \
  <<<"$output" || {
  printf 'policy output omitted the attempt inventory diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}
git -C "$architecture_dir" checkout -- \
  internal/operation/urlreference/attempt/contract.go
)

main "$@"
