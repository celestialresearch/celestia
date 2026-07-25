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

main() (
  local output
  local licence_dir
  local status
  local work_dir

  mkdir -p "$root/.cache"
  work_dir=$(mktemp -d "$root/.cache/verification-test.XXXXXX")
  case "$work_dir" in
  "$root"/.cache/verification-test.*) ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$work_dir" >&2
    return 1
    ;;
  esac
  trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM

  mkdir -p "$work_dir/.github/scripts" "$work_dir/a" "$work_dir/b"
  cp "$root/.github/scripts/coveragecheck.sh" \
    "$root/.github/scripts/policycheck.sh" \
    "$work_dir/.github/scripts/"
  printf 'default 90\ncache-max-age-minutes 0\n' \
    >"$work_dir/.github/.coverage"
  printf 'module probe.local/coverage\n\ngo 1.26.5\n' >"$work_dir/go.mod"
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

  set +e
  output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'coverage check accepted an under-covered package\n' >&2
    return 1
  }
  grep -Eq 'probe.local/coverage/a[[:space:]]+100\.00%' <<<"$output" || {
    printf 'coverage output omitted the fully covered package:\n%s\n' \
      "$output" >&2
    return 1
  }
  grep -Eq 'probe.local/coverage/b[[:space:]]+50\.00%' <<<"$output" || {
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
  (cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify >/dev/null)

  printf '%s\n' '// probe' >"$work_dir/coverage_test.go"
  set +e
  output=$(cd "$work_dir" && bash .github/scripts/policycheck.sh 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted coverage_test.go\n' >&2
    return 1
  }
  grep -Fq 'use an intent-named residual coverage file' <<<"$output" || {
    printf 'policy output omitted the rejected filename:\n%s\n' \
      "$output" >&2
    return 1
  }

  licence_dir="$work_dir/licence"
  mkdir -p "$licence_dir/.github/scripts"
  cp "$root/.github/scripts/licencecheck.sh" \
    "$licence_dir/.github/scripts/"
  git -C "$licence_dir" init -q
  git -C "$licence_dir" config core.autocrlf false
  printf '%s\n' '#!/usr/bin/env bash' >"$licence_dir/removed.sh"
  git -C "$licence_dir" add removed.sh
  rm -- "$licence_dir/removed.sh"
  (cd "$licence_dir" &&
    bash .github/scripts/licencecheck.sh verify >/dev/null)
)

main
