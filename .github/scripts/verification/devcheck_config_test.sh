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
work_dir=$(new_verification_work verification-devcheck-config)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-devcheck-config failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0
fake_bin="$work_dir/bin"
real_bash=$(command -v bash)
mkdir -p -- "$fake_bin"

set +e
output=$(
  cd "$root" &&
    DEVCHECK_PROFILE=invalid bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -eq 2 ]] || {
  printf 'devcheck accepted an unknown profile\n' >&2
  return 1
}
grep -Fq 'Unknown verification profile: invalid' <<<"$output" || {
  printf 'devcheck omitted the unknown-profile diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

set +e
output=$(
  cd "$root" &&
    DEVCHECK_PLATFORM_LINT=invalid DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -eq 2 ]] || {
  printf 'devcheck accepted an invalid platform-lint selection\n' >&2
  return 1
}
grep -Fq 'Invalid platform-lint selection: invalid' <<<"$output" || {
  printf 'platform-lint selection rejection omitted the diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

set +e
output=$(
  cd "$root" &&
    GOFLAGS='-run=^$' DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'devcheck accepted an inherited Go test filter\n' >&2
  return 1
}
grep -Fq 'Uncontrolled Go test environment: GOFLAGS' <<<"$output" || {
  printf 'Go test filter rejection omitted the diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

cat >"$fake_bin/bash" <<'EOF'
#!/bin/sh
case "$1" in
*.github/scripts/policycheck.sh)
  : >"$CELESTIA_POLICY_MARKER"
  exit
  ;;
*)
  : >"$CELESTIA_UNEXPECTED_SCRIPT_MARKER"
  exit 99
  ;;
esac
EOF
chmod +x "$fake_bin/bash"
set +e
output=$(
  cd "$root" &&
    CELESTIA_POLICY_MARKER="$work_dir/policy" \
    CELESTIA_UNEXPECTED_SCRIPT_MARKER="$work_dir/unexpected" \
    PATH="$fake_bin:$PATH" DEVCHECK_PROFILE=shell \
      "$real_bash" .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
if [[ "$status" -ne 0 || ! -e "$work_dir/policy" ||
  -e "$work_dir/unexpected" ]]; then
  printf 'bounded devcheck did not run only policy:\n%s\n' "$output" >&2
  return 1
fi

rm -- "$fake_bin/bash"
real_go=$(command -v go)
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = shellcheck ]; then
  shift 2
  printf '%s\n' "$*" >>"$CELESTIA_SHELLCHECK_LOG"
  case "$*" in
    *"$CELESTIA_SHELLCHECK_FAILURE"*)
      printf 'controlled ShellCheck failure: %s\n' \
        "$CELESTIA_SHELLCHECK_FAILURE" >&2
      exit 1
      ;;
  esac
  exit
fi
exec "$CELESTIA_REAL_GO" "$@"
EOF
chmod +x "$fake_bin/go"
for failed_path in \
  .github/scripts/actioncheck/cache_test.sh \
  .github/scripts/verification/coverage_test.sh; do
  shellcheck_log="$work_dir/shellcheck.log"
  : >"$shellcheck_log"
  set +e
  output=$(
    cd "$root" &&
      CELESTIA_REAL_GO="$real_go" \
      CELESTIA_SHELLCHECK_FAILURE="$failed_path" \
      CELESTIA_SHELLCHECK_LOG="$shellcheck_log" \
      PATH="$fake_bin:$PATH" DEVCHECK_PROFILE=config \
        "$real_bash" .github/scripts/devcheck.sh 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Config accepted a failed ShellCheck group: %s\n' "$failed_path" >&2
    return 1
  }
  grep -Fq "controlled ShellCheck failure: $failed_path" <<<"$output" || {
    printf 'Config omitted the ShellCheck failure: %s\n%s\n' \
      "$failed_path" "$output" >&2
    return 1
  }
  [[ $(wc -l <"$shellcheck_log") -eq 2 ]] || {
    printf 'Config did not run both ShellCheck groups: %s\n' "$failed_path" >&2
    return 1
  }
done
)

main
