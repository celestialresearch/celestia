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
work=$(mktemp -d "${TMPDIR:-/tmp}/testcheck-modes.XXXXXX")

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
if [[ -n "${GO_CALLS:-}" ]]; then
  printf '%s\n' "$*" >>"$GO_CALLS"
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
  if [[ "\${UNSORTED_INVENTORY:-false}" == true ]]; then
    printf '%s\\t%s\\n' 'fixture.invalid/z' 'TestZ'
    printf '%s\\t%s\\n' 'fixture.invalid/a' 'TestA'
    exit
  fi
  printf '%s\\t%s\\n' 'fixture.invalid/test' 'TestMustRun'
else
  printf '%s\\t%s\\n' '$work/package' '$work/bin/rust-test'
fi
EOF
chmod +x "$work/bin/testinventory"

cat >"$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${CARGO_LOG:?}"
if [[ "$1" == test && "$*" != *"--no-run"* ]]; then
  exit 2
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

selector=$work/selector
transform=internal/operation/urlreference/transform
mkdir -p "$selector/.github/scripts" "$selector/$transform" \
  "$selector/internal/use" "$selector/docs"
cp "$root/.github/scripts/testcheck.sh" "$selector/.github/scripts/testcheck.sh"
printf '.cache/\n' >"$selector/.gitignore"
cat >"$selector/go.mod" <<'EOF'
module fixture.invalid/selector

go 1.25.1
EOF
cat >"$selector/$transform/base.go" <<'EOF'
package transform

func Value() int { return 1 }
EOF
cat >"$selector/$transform/base_test.go" <<'EOF'
package transform

import "testing"

func TestValue(t *testing.T) { t.Helper() }
EOF
cat >"$selector/internal/use/use.go" <<'EOF'
package use

import "fixture.invalid/selector/internal/operation/urlreference/transform"

func Value() int { return transform.Value() }
EOF
printf 'fixture\n' >"$selector/docs/readme.md"
git -C "$selector" init -q
git -C "$selector" config user.name Fixture
git -C "$selector" config user.email fixture@example.invalid
git -C "$selector" config commit.gpgsign false
git -C "$selector" config core.autocrlf false
git -C "$selector" add -A
git -C "$selector" commit -q -m base

printf '\n' >>"$selector/$transform/base_test.go"
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ "$output" != fixture.invalid/selector/internal/operation/urlreference/transform ]]; then
  printf 'quick selection expanded a package-local test change:\n%s\n' \
    "$output" >&2
  exit 1
fi
git -C "$selector" checkout -q -- "$transform/base_test.go"

printf '\n' >>"$selector/$transform/base.go"
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ "$output" != $'fixture.invalid/selector/internal/operation/urlreference/transform\nfixture.invalid/selector/internal/use' ]]; then
  printf 'quick selection missed a reverse dependency:\n%s\n' "$output" >&2
  exit 1
fi
git -C "$selector" checkout -q -- "$transform/base.go"

printf '\n' >>"$selector/docs/readme.md"
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ -n "$output" ]]; then
  printf 'quick selection treated documentation as Go source:\n%s\n' \
    "$output" >&2
  exit 1
fi
git -C "$selector" checkout -q -- docs/readme.md

git -C "$selector" rm -q "$transform/base_test.go"
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ "$output" != ./... ]]; then
  printf 'quick selection did not fail closed for a deletion:\n%s\n' \
    "$output" >&2
  exit 1
fi
git -C "$selector" reset -q --hard HEAD

cat >"$selector/$transform/platform.go" <<'EOF'
//go:build windows

package transform
EOF
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ "$output" != ./... ]]; then
  printf 'quick selection did not fail closed for a build constraint:\n%s\n' \
    "$output" >&2
  exit 1
fi
rm -f -- "$selector/$transform/platform.go"

cat >"$selector/$transform/platform_windows_test.go" <<'EOF'
package transform

import "testing"

func TestPlatform(t *testing.T) { t.Helper() }
EOF
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ "$output" != ./... ]]; then
  printf 'quick selection ignored an implicit platform constraint:\n%s\n' \
    "$output" >&2
  exit 1
fi
rm -f -- "$selector/$transform/platform_windows_test.go"

printf 'unknown\n' >"$selector/unknown.file"
output=$(bash "$selector/.github/scripts/testcheck.sh" go-packages)
if [[ "$output" != ./... ]]; then
  printf 'quick selection did not fail closed for an unknown path:\n%s\n' \
    "$output" >&2
  exit 1
fi
rm -f -- "$selector/unknown.file"

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

GO_CALLS="$work/go-calls" PATH="$work/bin:$PATH" \
  TESTINVENTORY_BIN="$work/bin/testinventory" COMPLETE_TEST=true \
  bash "$root/.github/scripts/testcheck.sh" go standard \
    "$work/coverage.out" --fixture >/dev/null
if ! grep -Fq -- '-count=1 -shuffle=on -covermode=atomic' "$work/go-calls" ||
  ! grep -Fq -- "-coverprofile=$work/coverage.out" "$work/go-calls"; then
  printf 'standard completion check omitted atomic coverage:\n' >&2
  cat "$work/go-calls" >&2
  exit 1
fi

set +e
output=$(
  UNSORTED_INVENTORY=true PATH="$work/bin:$PATH" \
    TESTINVENTORY_BIN="$work/bin/testinventory" COMPLETE_TEST=true \
    bash "$root/.github/scripts/testcheck.sh" go quick --fixture 2>&1
)
status=$?
set -e
if [[ "$status" -eq 0 ]] ||
  [[ "$output" != *'Go test inventory comparison failed'* ]]; then
  printf 'Go completion check accepted an unsorted inventory:\n%s\n' \
    "$output" >&2
  exit 1
fi

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
PATH="$work/bin:$PATH" CARGO_BIN="$work/bin/cargo" CARGO_LOG="$work/cargo.log" \
  TESTINVENTORY_BIN="$work/bin/testinventory" \
  COMPLETE_TEST=true EXPECTED_PACKAGE_ROOT="$work/package" \
  bash "$root/.github/scripts/testcheck.sh" rust unused --fixture >/dev/null
if grep -Fv -- '--all-features' "$work/cargo.log" >/dev/null; then
  printf 'Rust completion check omitted all features:\n' >&2
  cat "$work/cargo.log" >&2
  exit 1
fi
if grep -Fv -- '--no-run' "$work/cargo.log" >/dev/null ||
  [[ $(wc -l <"$work/cargo.log") -ne 2 ]]; then
  printf 'Rust completion check repeated ordinary test execution:\n' >&2
  cat "$work/cargo.log" >&2
  exit 1
fi
