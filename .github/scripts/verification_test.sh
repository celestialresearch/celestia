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
  local repo_dir
  local licence_dir
  local rust_dir
  local status
  local work_dir
  local change_pid=
  local currency_pid=

  # shellcheck disable=SC2329 # Invoked by the EXIT and signal trap.
  cleanup() {
    if [[ -n "$change_pid" ]]; then
      kill "$change_pid" 2>/dev/null || true
      wait "$change_pid" 2>/dev/null || true
    fi
    if [[ -n "$currency_pid" ]]; then
      kill "$currency_pid" 2>/dev/null || true
      wait "$currency_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work_dir"
  }

  mkdir -p "$root/.cache"
  work_dir=$(mktemp -d "$root/.cache/verification-test.XXXXXX")
  case "$work_dir" in
  "$root"/.cache/verification-test.*) ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$work_dir" >&2
    return 1
    ;;
  esac
  trap cleanup EXIT HUP INT TERM
  bash "$root/.github/scripts/changecheck_test.sh" &
  change_pid=$!
  bash "$root/.github/scripts/currencycheck_test.sh" &
  currency_pid=$!

  mkdir -p "$work_dir/.github/scripts" "$work_dir/a" "$work_dir/b"
  cp "$root/.github/scripts/coveragecheck.sh" \
    "$root/.github/scripts/policycheck.sh" \
    "$work_dir/.github/scripts/"
  printf 'default 90\ncache-max-age-minutes 0\n' \
    >"$work_dir/.github/.coverage"
  printf 'module probe.local/coverage\n\ngo 1.26.5\n' >"$work_dir/go.mod"
  git -C "$work_dir" init -q

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

  rust_dir="$work_dir/rust"
  mkdir -p "$rust_dir/.github/scripts" "$rust_dir/.github/workflows" \
    "$rust_dir/bin"
  cp "$root/.github/scripts/rustcheck.sh" "$rust_dir/.github/scripts/"
  cat >"$rust_dir/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"

[workspace.package]
rust-version = "1.94.1"
EOF
  printf '%s\n' '[toolchain]' 'channel = "1.94.0"' \
    >"$rust_dir/rust-toolchain.toml"
  cat >"$rust_dir/.github/workflows/main.yml" <<'EOF'
steps:
  - name: Unrelated
    with:
      tool: |
        rust@1.94.1 + ignored
  - name: Setup
    uses: taiki-e/install-action@0123456789012345678901234567890123456789
    with:
      tool: |
        rust@1.94.1 + rustfmt + clippy
        cargo-llvm-cov@0.8.7
        cargo-audit@0.22.2
        cargo-deny@0.20.2
EOF
  cp "$rust_dir/.github/workflows/main.yml" \
    "$rust_dir/.github/workflows/main.yml.base"

  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted mismatched versions\n' >&2
    return 1
  }
  grep -Fq \
    'Rust version mismatch: manifest=1.94.1 toolchain=1.94.0 workflow=1.94.1' \
    <<<"$output" || {
    printf 'Rust config check omitted the mismatch diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }

  rm -- "$rust_dir/rust-toolchain.toml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted an incomplete workspace\n' >&2
    return 1
  }
  grep -Fq 'Incomplete Rust configuration' <<<"$output" || {
    printf 'Rust config check omitted the incomplete diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }

  printf '%s\n' '[toolchain]' 'channel = "1.94.1"' \
    >"$rust_dir/rust-toolchain.toml"
  (cd "$rust_dir" && bash .github/scripts/rustcheck.sh config)

  mv "$rust_dir/Cargo.toml" "$rust_dir/Cargo.toml.saved"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  mv "$rust_dir/Cargo.toml.saved" "$rust_dir/Cargo.toml"
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted workflow-only configuration\n' >&2
    return 1
  }

  {
    printf '%s\n' '# rust@1.94.1'
    sed 's/rust@1.94.1 +/rust@1.94.0 +/' \
      "$rust_dir/.github/workflows/main.yml.base"
  } >"$rust_dir/.github/workflows/main.yml.new"
  mv "$rust_dir/.github/workflows/main.yml.new" \
    "$rust_dir/.github/workflows/main.yml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted a matching commented version\n' >&2
    return 1
  }
  cp "$rust_dir/.github/workflows/main.yml.base" \
    "$rust_dir/.github/workflows/main.yml"

  sed '/^[[:space:]]*rust@1.94.1 + rustfmt + clippy$/a\
        rust@1.94.1 + rustfmt' \
    "$rust_dir/.github/workflows/main.yml.base" \
    >"$rust_dir/.github/workflows/main.yml.new"
  mv "$rust_dir/.github/workflows/main.yml.new" \
    "$rust_dir/.github/workflows/main.yml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted duplicate active pins\n' >&2
    return 1
  }
  grep -Fq 'Expected one active workflow pin for rust, found 2' \
    <<<"$output" || {
    printf 'Rust config check omitted the duplicate diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  cp "$rust_dir/.github/workflows/main.yml.base" \
    "$rust_dir/.github/workflows/main.yml"

  cat >"$rust_dir/bin/cargo" <<'EOF'
#!/usr/bin/env bash
case "$1" in
llvm-cov) printf 'cargo-llvm-cov %s\n' "${LLVM_COV_VERSION:-0.8.7}" ;;
audit)
  [[ "${FAIL_SUPPLY_COMMANDS:-false}" == false ]] || exit 9
  printf 'cargo-audit %s\n' "${AUDIT_VERSION:-0.22.2}"
  ;;
deny)
  [[ "${FAIL_SUPPLY_COMMANDS:-false}" == false ]] || exit 9
  printf 'cargo-deny %s\n' "${DENY_VERSION:-0.20.2}"
  ;;
*) exit 2 ;;
esac
EOF
  chmod +x "$rust_dir/bin/cargo"
  cat >"$rust_dir/bin/rustc" <<'EOF'
#!/usr/bin/env bash
printf 'rustc %s\n' "${FIXTURE_RUSTC_VERSION:-1.94.1}"
EOF
  chmod +x "$rust_dir/bin/rustc"
  unset FIXTURE_RUSTC_VERSION

  (
    cd "$rust_dir" &&
      PATH="$rust_dir/bin:$PATH" bash .github/scripts/rustcheck.sh tools
  )
  set +e
  output=$(
    cd "$rust_dir" &&
      PATH="$rust_dir/bin:$PATH" FIXTURE_RUSTC_VERSION=0 \
        bash .github/scripts/rustcheck.sh tools 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust tool check accepted a mismatched compiler version\n' >&2
    return 1
  }
  grep -Fq 'Rust compiler version mismatch: expected=1.94.1 actual=0' \
    <<<"$output" || {
    printf 'Rust tool check omitted the compiler mismatch diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  (
    cd "$rust_dir" &&
      PATH="$rust_dir/bin:$PATH" DEVCHECK_SUPPLY_CHAIN=false \
        FAIL_SUPPLY_COMMANDS=true bash .github/scripts/rustcheck.sh tools
  )

  for mismatch in llvm-cov audit deny; do
    set +e
    case "$mismatch" in
    llvm-cov)
      output=$(
        cd "$rust_dir" &&
          PATH="$rust_dir/bin:$PATH" DEVCHECK_SUPPLY_CHAIN=true \
            LLVM_COV_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    audit)
      output=$(
        cd "$rust_dir" &&
          PATH="$rust_dir/bin:$PATH" DEVCHECK_SUPPLY_CHAIN=true \
            AUDIT_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    deny)
      output=$(
        cd "$rust_dir" &&
          PATH="$rust_dir/bin:$PATH" DEVCHECK_SUPPLY_CHAIN=true \
            DENY_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    esac
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || {
      printf 'Rust tool check accepted a mismatched %s version\n' \
        "$mismatch" >&2
      return 1
    }
    grep -Fq 'Rust helper version mismatch' <<<"$output" || {
      printf 'Rust tool check omitted the %s mismatch diagnostic:\n%s\n' \
        "$mismatch" "$output" >&2
      return 1
    }
  done

  repo_dir="$work_dir/repo"
  mkdir -p "$repo_dir"
  tar -cf - -C "$root" \
    .github/codeql .github/scripts .github/workflows \
    .github/.coverage .github/.currency .github/dependabot.yml \
    docs internal policies worker \
    .editorconfig .gitattributes .gitignore .golangci.yml \
    AGENTS.md Cargo.lock Cargo.toml deny.toml go.mod go.sum LICENSE README.md \
    rust-toolchain.toml |
    tar -xf - -C "$repo_dir"
  git -C "$repo_dir" init -q
  git -C "$repo_dir" config core.autocrlf false
  git -C "$repo_dir" add -A
  rm -- "$repo_dir/rust-toolchain.toml"
  set +e
  output=$(
    cd "$repo_dir" &&
      DEVCHECK_PROFILE=shell DEVCHECK_CURRENCY=false \
        DEVCHECK_SELF_TEST=false \
        bash .github/scripts/devcheck.sh 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'devcheck accepted incomplete Rust configuration\n' >&2
    return 1
  }
  if ! grep -Fq 'Config' <<<"$output" ||
    ! grep -Fq 'Incomplete Rust configuration' <<<"$output"; then
    printf 'devcheck omitted the incomplete Rust diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  fi

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

  wait "$change_pid"
  change_pid=
  wait "$currency_pid"
  currency_pid=
)

main
