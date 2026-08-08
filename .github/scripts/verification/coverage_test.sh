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
printf '%s\n' 'default 90' >"$work_dir/.github/.coverage"
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
[[ "$output" == *'b/b.go:'*'Second'*'0.0%'* ]] || {
  printf 'coverage output omitted the uncovered function:\n%s\n' \
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
[[ "$output" == *'b/b.go:'*'Second'*'0.0%'* ]] || {
  printf 'coverage enforcement omitted the uncovered function:\n%s\n' \
    "$output" >&2
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

cat >"$work_dir/target.out" <<'EOF'
mode: atomic
celestia.research/coverage/a/a.go:1.1,1.2 19 1
celestia.research/coverage/a/a.go:2.1,2.2 1 0
EOF
mkdir -p "$work_dir/target-bin"
cat >"$work_dir/target-bin/go" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
env)
  case "${2:-}" in
  GOOS) printf '%s\n' "$COVERAGE_TEST_GOOS" ;;
  GOARCH) printf '%s\n' "$COVERAGE_TEST_GOARCH" ;;
  *) exit 2 ;;
  esac
  ;;
tool)
  [[ "${2:-}" == dist && "${3:-}" == list ]] || exit 2
  printf '%s\n' linux/amd64 windows/amd64
  ;;
list) printf '%s\n' celestia.research/coverage/a celestia.research/coverage/b ;;
test) exec "$REAL_GO" "$@" ;;
*) exit 2 ;;
esac
EOF
chmod +x "$work_dir/target-bin/go"

printf '%s\n' 'default 90' \
  'package windows amd64 celestia.research/coverage/a 96' \
  >"$work_dir/.github/.coverage"
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'targeted coverage floor did not apply on Windows\n' >&2
  return 1
}
output=$(cd "$work_dir" && REAL_GO="$real_go" \
  COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh verify 2>&1) || {
  printf 'targeted coverage verification rejected Windows:\n%s\n' "$output" >&2
  return 1
}

output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=linux COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1) || {
  printf 'inactive target coverage floor rejected Linux:\n%s\n' "$output" >&2
  return 1
}

printf '%s\n' 'default 90' \
  'package windows amd64 celestia.research/celestia/internal/testcargo 75' \
  >"$work_dir/.github/.coverage"
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=linux COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1) || {
  printf 'inactive package policy rejected Linux:\n%s\n' "$output" >&2
  return 1
}
output=$(cd "$work_dir" && REAL_GO="$real_go" \
  COVERAGE_TEST_GOOS=linux COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh verify 2>&1) || {
  printf 'inactive package policy rejected Linux verification:\n%s\n' "$output" >&2
  return 1
}
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] ||
  [[ "$output" != *'coverage policy names unknown package '* ]]; then
  printf 'applicable missing package was accepted:\n%s\n' "$output" >&2
  return 1
fi

printf '%s\n' 'default 90' \
  'package windows amd64 celestia.research/coverage/b 75' \
  >"$work_dir/.github/.coverage"
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] ||
  [[ "$output" != *'coverage policy names package without coverage '* ]]; then
  printf 'applicable package without coverage was accepted:\n%s\n' "$output" >&2
  return 1
fi

printf '%s\n' 'default 90' \
  'package windows notreal celestia.research/coverage/a 95' \
  >"$work_dir/.github/.coverage"
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=linux COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] || [[ "$output" != *'unknown Go target'* ]]; then
  printf 'unknown Go target was accepted:\n%s\n' "$output" >&2
  return 1
fi

printf '%s\n' 'default 90' \
  'package windows amd64 celestia.research/coverage/a 95' \
  'package windows amd64 celestia.research/coverage/a 95' \
  >"$work_dir/.github/.coverage"
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] || [[ "$output" != *'duplicate coverage policy'* ]]; then
  printf 'duplicate target coverage policy was accepted:\n%s\n' "$output" >&2
  return 1
fi

printf '%s\n' 'default 90' \
  'package windows amd64 celestia.research/coverage/a 95 extra' \
  >"$work_dir/.github/.coverage"
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] || [[ "$output" != *'invalid package coverage policy'* ]]; then
  printf 'malformed target coverage policy was accepted:\n%s\n' "$output" >&2
  return 1
fi

printf '%s\n' 'default 90' \
  'package celestia.research/coverage/a 95' \
  >"$work_dir/.github/.coverage"
set +e
output=$(cd "$work_dir" && COVERAGE_TEST_GOOS=windows COVERAGE_TEST_GOARCH=amd64 \
  PATH="$work_dir/target-bin:$PATH" \
  bash .github/scripts/coveragecheck.sh enforce "$work_dir/target.out" 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] || [[ "$output" != *'invalid package coverage policy'* ]]; then
  printf 'untargeted package coverage policy was accepted:\n%s\n' "$output" >&2
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
