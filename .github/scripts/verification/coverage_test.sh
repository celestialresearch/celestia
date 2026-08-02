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
root=$(cd -- "$script_dir/../../.." && pwd)
work_dir=$(new_verification_work verification-coverage)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-coverage failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

mkdir -p "$work_dir/.github/scripts" "$work_dir/a" "$work_dir/b"
cp "$root/.github/scripts/coveragecheck.sh" "$work_dir/.github/scripts/"
cp "$root/.github/.coverage" "$work_dir/.github/.coverage"
printf '%s\n' 'module celestia.research/coverage' '' 'go 1.26.5' >"$work_dir/go.mod"
git -C "$work_dir" init -q
cat >"$work_dir/a/a.go" <<'EOF'
package a

func Value() bool { return true }
EOF
cat >"$work_dir/a/a_test.go" <<'EOF'
package a

import "testing"

func TestValue(t *testing.T) {
	if !Value() {
		t.Fatal("value is false")
	}
}
EOF
cat >"$work_dir/b/b.go" <<'EOF'
package b

func First() bool { return true }
func Second() bool { return true }
EOF
cat >"$work_dir/b/b_test.go" <<'EOF'
package b

import "testing"

func TestFirst(t *testing.T) {
	if !First() {
		t.Fatal("first is false")
	}
}
EOF

cat >"$work_dir/b/failure_test.go" <<'EOF'
package b

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestFailure(t *testing.T) {
	fmt.Fprintln(os.Stderr, strings.Repeat("x", 131072))
	fmt.Fprintln(os.Stderr, "fixture failure")
	t.Fatal("failed")
}
EOF
set +e
output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1)
status=$?
set -e
rm -- "$work_dir/b/failure_test.go"
[[ "$status" -ne 0 ]] || {
  printf 'coverage check accepted a failing test\n' >&2
  return 1
}
if [[ "$output" == *'unbound variable'* ]]; then
  printf 'coverage cleanup masked a failing test:\n%s\n' "$output" >&2
  return 1
fi
[[ "$output" == *'fixture failure'* ]] || {
  printf 'coverage check discarded failing test output:\n%s\n' "$output" >&2
  return 1
}
((${#output} <= 70000)) || {
  printf 'coverage check retained unbounded failing output\n' >&2
  return 1
}

set +e
output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'coverage check accepted an under-covered package\n' >&2
  return 1
}
grep -Eq 'celestia\.research/coverage/a[[:space:]]+100\.00%' \
  <<<"$output" || {
  printf 'coverage output omitted the fully covered package:\n%s\n' \
    "$output" >&2
  return 1
}
grep -Eq 'celestia\.research/coverage/b[[:space:]]+50\.00%' \
  <<<"$output" || {
  printf 'coverage output omitted the under-covered package:\n%s\n' \
    "$output" >&2
  return 1
}

cat >>"$work_dir/b/b_test.go" <<'EOF'

func TestSecond(t *testing.T) {
	if !Second() {
		t.Fatal("second is false")
	}
}
EOF
output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1) || {
  printf 'coverage check rejected the fully covered fixture:\n%s\n' \
    "$output" >&2
  return 1
}
(
  cd "$work_dir" &&
    bash .github/scripts/coveragecheck.sh cached >/dev/null
)
mv -- "$work_dir/b/b_test.go" "$work_dir/b/b_plan9_test.go"
set +e
output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh cached 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'coverage cache ignored a build-sensitive filename change\n' >&2
  return 1
}
mv -- "$work_dir/b/b_plan9_test.go" "$work_dir/b/b_test.go"
fake_bin="$work_dir/fake-bin"
real_git=$(command -v git)
mkdir -p "$fake_bin"
cat >"$fake_bin/git" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "${FAIL_GIT_COMMAND:-}" ]]; then
  exit 2
fi
exec "$REAL_GIT" "$@"
EOF
chmod +x "$fake_bin/git"
set +e
output=$(
  cd "$work_dir" &&
    CELESTIA_GIT_BIN="$fake_bin/git" FAIL_GIT_COMMAND=ls-files \
      REAL_GIT="$real_git" \
      bash .github/scripts/coveragecheck.sh cached 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'coverage check ignored a failed source inventory\n' >&2
  return 1
}
grep -Fq 'Failed to inventory coverage inputs' <<<"$output" || {
  printf 'coverage output omitted the inventory failure:\n%s\n' \
    "$output" >&2
  return 1
}
)

main
