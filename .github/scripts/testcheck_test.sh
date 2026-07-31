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
