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
(
  cd "$work_dir"
  go test -covermode=atomic -coverprofile="$work_dir/under.out" ./...
) >/dev/null
set +e
output=$(cd "$work_dir" && \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/under.out" 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'coverage enforcement accepted an under-covered profile\n' >&2
  return 1
}
sed '1s/atomic/count/' "$work_dir/under.out" >"$work_dir/non-atomic.out"
set +e
output=$(cd "$work_dir" && \
  bash .github/scripts/coveragecheck.sh enforce \
    "$work_dir/non-atomic.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] ||
  [[ "$output" != *'coverage profile is not atomic'* ]]; then
  printf 'coverage enforcement accepted a non-atomic profile:\n%s\n' \
    "$output" >&2
  return 1
fi

cat >>"$work_dir/b/b_test.go" <<'EOF'

func TestSecond(t *testing.T) {
	if !Second() {
		t.Fatal("second is false")
	}
}
EOF
real_go=$(command -v go)
mkdir -p "$work_dir/go-bin"
cat >"$work_dir/go-bin/go" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == test ]]; then
  printf '%s\n' "$*" >>"$GO_CALLS"
fi
exec "$REAL_GO" "$@"
EOF
chmod +x "$work_dir/go-bin/go"
output=$(
  cd "$work_dir" &&
    GO_CALLS="$work_dir/go-calls" REAL_GO="$real_go" \
      PATH="$work_dir/go-bin:$PATH" \
      bash .github/scripts/coveragecheck.sh verify 2>&1
) || {
  printf 'coverage check rejected the fully covered fixture:\n%s\n' \
    "$output" >&2
  return 1
}
(
  cd "$work_dir"
  go test -covermode=atomic -coverprofile="$work_dir/complete.out" ./...
) >/dev/null
(
  cd "$work_dir"
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/complete.out"
) >/dev/null || {
  printf 'coverage enforcement rejected a complete profile\n' >&2
  return 1
}
if [[ $(grep -c '^test ' "$work_dir/go-calls") -ne 1 ]] ||
  ! grep -Fq ' ./...' "$work_dir/go-calls"; then
  printf 'coverage check did not use one workspace test invocation:\n' >&2
  cat "$work_dir/go-calls" >&2
  return 1
fi
mv -- "$work_dir/b/b_test.go" "$work_dir/b/b_plan9_test.go"
set +e
output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'coverage check ignored a build-sensitive filename change\n' >&2
  return 1
}
mv -- "$work_dir/b/b_plan9_test.go" "$work_dir/b/b_test.go"
)

main
