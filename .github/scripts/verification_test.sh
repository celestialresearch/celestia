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
cache_root=${CELESTIA_CACHE_DIR:-"$root/.cache"}

main() (
  local output
  local repo_dir
  local fake_bin
  local licence_dir
  local metadata_probe
  local real_git
  local rust_dir
  local shellcheck_script
  local status
  local work_dir
  local action_pid=
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
    if [[ -n "$action_pid" ]]; then
      kill "$action_pid" 2>/dev/null || true
      wait "$action_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work_dir"
  }

  mkdir -p "$cache_root"
  work_dir=$(mktemp -d "$cache_root/verification-test.XXXXXX")
  case "$work_dir" in
  "$cache_root"/verification-test.*) ;;
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
  bash "$root/.github/scripts/actioncheck_test.sh" &
  action_pid=$!

  shellcheck_script="$root/.github/scripts/windows-shellcheck.ps1"
  if grep -Fq '| head' "$shellcheck_script"; then
    printf 'Windows shell check uses an unowned output pipeline\n' >&2
    return 1
  fi
  if grep -Eq "find .*'-name '\\*\\.go'.*\\|.*grep" \
    "$root/.github/workflows/compatibility.yml"; then
    printf 'compatibility check masks Go inventory failures\n' >&2
    return 1
  fi
  for variable in CELESTIA_SHELL_CACHE CELESTIA_SHELL_TARGET \
    CELESTIA_SHELL_TMP; do
    grep -Fq "\$start.Environment['$variable']" "$shellcheck_script" || {
      printf 'Windows shell check omits %s isolation\n' "$variable" >&2
      return 1
    }
  done
  grep -Fq 'exec /usr/bin/bash ./.github/scripts/devcheck.sh' \
    "$shellcheck_script" || {
    printf 'Windows shell check does not own devcheck\n' >&2
    return 1
  }
  grep -Fq "\$start.RedirectStandardOutput = \$true" \
    "$shellcheck_script" || {
    printf 'Windows shell check does not own standard output\n' >&2
    return 1
  }
  grep -Fq "\$start.RedirectStandardError = \$true" \
    "$shellcheck_script" || {
    printf 'Windows shell check does not own standard error\n' >&2
    return 1
  }
  grep -Fq "\$Stream.ReadAsync(" "$shellcheck_script" || {
    printf 'Windows shell check does not use bounded stream reads\n' >&2
    return 1
  }
  if grep -Eq 'Get-Content .*-(Raw|ReadCount)' "$shellcheck_script"; then
    printf 'Windows shell check reads captured output without a bound\n' >&2
    return 1
  fi
  # shellcheck disable=SC2016 # These probes match literal source.
  grep -Fq '$cleanupFailures = @(' "$shellcheck_script" || {
    printf 'Windows shell check does not retain cleanup failures as an array\n' >&2
    return 1
  }
  # shellcheck disable=SC2016 # These probes match literal source.
  grep -Fq 'CYGWIN*) go_profile=$(cygpath -w "$profile")' \
    "$root/.github/scripts/coveragecheck.sh" || {
    printf 'coverage check omits Cygwin Go-path conversion\n' >&2
    return 1
  }

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
    "$rust_dir/bin" "$rust_dir/worker/qualification-fixtures"
  cp "$root/.github/scripts/rustcheck.sh" "$rust_dir/.github/scripts/"
  cat >"$rust_dir/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"

[workspace.package]
rust-version = "1.94.1"
EOF
  printf '%s\n' '[toolchain]' 'channel = "1.94.0"' \
    >"$rust_dir/rust-toolchain.toml"
  printf '%s\n' '[package]' 'rust-version = "1.94.1"' \
    >"$rust_dir/worker/qualification-fixtures/Cargo.toml"
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
  cp "$rust_dir/.github/workflows/main.yml" \
    "$rust_dir/.github/workflows/nightly.yml"

  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted mismatched versions\n' >&2
    return 1
  }
  grep -Fq \
    'Rust version mismatch: manifest=1.94.1 fixture=1.94.1 toolchain=1.94.0 workflow=1.94.1' \
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

  printf '%s\n' '[package]' 'rust-version = "1.94.0"' \
    >"$rust_dir/worker/qualification-fixtures/Cargo.toml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted fixture version drift\n' >&2
    return 1
  }
  grep -Fq 'fixture=1.94.0' <<<"$output" || {
    printf 'Rust config check omitted fixture drift:\n%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' '[package]' 'rust-version = "1.94.1"' \
    >"$rust_dir/worker/qualification-fixtures/Cargo.toml"

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

  sed 's/rust@1.94.1 +/rust@1.94.0 +/' \
    "$rust_dir/.github/workflows/main.yml.base" \
    >"$rust_dir/.github/workflows/nightly.yml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted cross-workflow pin drift\n' >&2
    return 1
  }
  grep -Fq 'Expected one active workflow version for rust, found 2' \
    <<<"$output" || {
    printf 'Rust config check omitted the cross-workflow diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  cp "$rust_dir/.github/workflows/main.yml.base" \
    "$rust_dir/.github/workflows/nightly.yml"

  cat >"$rust_dir/bin/cargo" <<'EOF'
#!/usr/bin/env bash
case "$1" in
build)
  shift
  target_dir=
  while [[ $# -gt 0 ]]; do
    case "$1" in
    --target-dir)
      shift
      target_dir=${1:-}
      ;;
    esac
    shift || exit 2
  done
  [[ -n "$target_dir" ]] || exit 2
  release_dir="$target_dir/release"
  mkdir -p "$release_dir"
  suffix=
  case "$(uname -s 2>/dev/null)" in
  CYGWIN* | MINGW* | MSYS*) suffix=.exe ;;
  esac
  : >"$release_dir/celestia-url-reference$suffix"
  chmod +x "$release_dir/celestia-url-reference$suffix"
  : >"$release_dir/celestia-url-reference.d"
  if [[ "${RUSTCHECK_EXECUTABLE_METADATA:-false}" == true ]]; then
    chmod +x "$release_dir/celestia-url-reference.d"
  fi
  if [[ -n "${RUSTCHECK_EXTRA_RELEASE_EXECUTABLE:-}" ]]; then
    : >"$release_dir/${RUSTCHECK_EXTRA_RELEASE_EXECUTABLE}${suffix}"
    chmod +x "$release_dir/${RUSTCHECK_EXTRA_RELEASE_EXECUTABLE}${suffix}"
  fi
  if [[ -n "${RUSTCHECK_EXTRA_RELEASE_ARTEFACT:-}" ]]; then
    : >"$release_dir/${RUSTCHECK_EXTRA_RELEASE_ARTEFACT}"
  fi
  if [[ -n "${RUSTCHECK_NESTED_RELEASE_ARTEFACT:-}" ]]; then
    mkdir -p "$release_dir/nested"
    : >"$release_dir/nested/${RUSTCHECK_NESTED_RELEASE_ARTEFACT}"
  fi
  ;;
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
      RUSTC_BIN="$rust_dir/bin/rustc" \
        CARGO_BIN="$rust_dir/bin/cargo" \
        bash .github/scripts/rustcheck.sh tools
  )
  set +e
  output=$(
    cd "$rust_dir" &&
      RUSTC_BIN="$rust_dir/bin/rustc" \
        CARGO_BIN="$rust_dir/bin/cargo" FIXTURE_RUSTC_VERSION=0 \
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
      RUSTC_BIN="$rust_dir/bin/rustc" \
        CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=false \
        FAIL_SUPPLY_COMMANDS=true bash .github/scripts/rustcheck.sh tools
  )

  for mismatch in llvm-cov audit deny; do
    set +e
    case "$mismatch" in
    llvm-cov)
      output=$(
        cd "$rust_dir" &&
          RUSTC_BIN="$rust_dir/bin/rustc" \
            CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=true \
            LLVM_COV_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    audit)
      output=$(
        cd "$rust_dir" &&
          RUSTC_BIN="$rust_dir/bin/rustc" \
            CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=true \
            AUDIT_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    deny)
      output=$(
        cd "$rust_dir" &&
          RUSTC_BIN="$rust_dir/bin/rustc" \
            CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=true \
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

  (
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        bash .github/scripts/rustcheck.sh artefacts
  )
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        RUSTCHECK_EXTRA_RELEASE_EXECUTABLE=celestia-hostile-worker \
        bash .github/scripts/rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust artefact check accepted an unexpected executable\n' >&2
    return 1
  }
  grep -Fq 'Unexpected release executable: celestia-hostile-worker' \
    <<<"$output" || {
    printf 'Rust artefact check omitted the unexpected executable:\n%s\n' \
      "$output" >&2
    return 1
  }
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        RUSTCHECK_EXTRA_RELEASE_ARTEFACT=unexpected.metadata \
        bash .github/scripts/rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust artefact check accepted an unexpected regular file\n' >&2
    return 1
  }
  grep -Fq 'Unexpected release artefact: unexpected.metadata' \
    <<<"$output" || {
    printf 'Rust artefact check omitted the unexpected regular file:\n%s\n' \
      "$output" >&2
    return 1
  }
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        RUSTCHECK_NESTED_RELEASE_ARTEFACT=unexpected.nested \
        bash .github/scripts/rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust artefact check accepted a nested regular file\n' >&2
    return 1
  }
  grep -Fq 'Unexpected release directory: nested' \
    <<<"$output" || {
    printf 'Rust artefact check omitted the nested release directory:\n%s\n' \
      "$output" >&2
    return 1
  }
  metadata_probe="$rust_dir/executable.d"
  : >"$metadata_probe"
  chmod +x "$metadata_probe"
  if [[ -x "$metadata_probe" ]]; then
    set +e
    output=$(
      cd "$rust_dir" &&
        CARGO_BIN="$rust_dir/bin/cargo" RUSTCHECK_EXECUTABLE_METADATA=true \
          bash .github/scripts/rustcheck.sh artefacts 2>&1
    )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || {
      printf 'Rust artefact check accepted executable metadata\n' >&2
      return 1
    }
    grep -Fq 'Invalid release metadata: celestia-url-reference.d' \
      <<<"$output" || {
      printf 'Rust artefact check omitted executable metadata:\n%s\n' \
        "$output" >&2
      return 1
    }
  fi

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

  cat >"$work_dir/b/failure_test.go" <<'EOF'
package b

import "testing"

func TestFailure(t *testing.T) {
	t.Fatal("fixture failure")
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
  if grep -Fq 'unbound variable' <<<"$output"; then
    printf 'coverage cleanup masked a failing test:\n%s\n' "$output" >&2
    return 1
  fi

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
  {
    printf '%s\n' '// Code generated by fixture. DO NOT EDIT.'
    awk 'BEGIN { for (line = 0; line < 801; line++) print "// fixture" }'
  } >"$work_dir/-generated.go"
  set +e
  output=$(cd "$work_dir" && bash .github/scripts/policycheck.sh 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy fixture unexpectedly satisfied the module policy\n' >&2
    return 1
  }
  if grep -Eq 'invalid option|generated.go: source file exceeds' <<<"$output"; then
    printf 'policy check misread an option-like generated filename:\n%s\n' \
      "$output" >&2
    return 1
  fi
  rm -- "$work_dir/-generated.go"

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
      FAIL_GIT_COMMAND=grep REAL_GIT="$real_git" PATH="$fake_bin:$PATH" \
        bash .github/scripts/policycheck.sh 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check ignored a failed scanner\n' >&2
    return 1
  }
  grep -Fq 'git grep failed while enforcing repository policy' <<<"$output" || {
    printf 'policy output omitted the scanner failure:\n%s\n' "$output" >&2
    return 1
  }
  set +e
  output=$(
    cd "$work_dir" &&
      FAIL_GIT_COMMAND=ls-files REAL_GIT="$real_git" PATH="$fake_bin:$PATH" \
        bash .github/scripts/coveragecheck.sh cached 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'coverage check ignored a failed source inventory\n' >&2
    return 1
  }

  licence_dir="$work_dir/licence"
  mkdir -p "$licence_dir/.github/scripts"
  cp "$root/.github/scripts/licencecheck.sh" \
    "$licence_dir/.github/scripts/"
  git -C "$licence_dir" init -q
  git -C "$licence_dir" config core.autocrlf false
  set +e
  output=$(
    cd "$licence_dir" &&
      FAIL_GIT_COMMAND=ls-files REAL_GIT="$real_git" PATH="$fake_bin:$PATH" \
        bash .github/scripts/licencecheck.sh verify 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'licence check ignored a failed file inventory\n' >&2
    return 1
  }
  printf '%s\n' '#!/usr/bin/env bash' >"$licence_dir/removed.sh"
  git -C "$licence_dir" add removed.sh
  rm -- "$licence_dir/removed.sh"
  (cd "$licence_dir" &&
    bash .github/scripts/licencecheck.sh verify >/dev/null)
  printf '%s\n' 'package fixture' >"$licence_dir/fixture.go"
  (
    cd "$licence_dir" &&
      bash .github/scripts/licencecheck.sh apply >/dev/null &&
      bash .github/scripts/licencecheck.sh cached-diff >/dev/null
  )
  mv -- "$licence_dir/fixture.go" "$licence_dir/-fixture.sh"
  set +e
  output=$(
    cd "$licence_dir" &&
      bash .github/scripts/licencecheck.sh cached-diff 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'licence cache ignored a filename-dependent header change\n' >&2
    return 1
  }
  grep -Fq -- '-fixture.sh: missing or incorrect proprietary header' <<<"$output" || {
    printf 'licence cache did not report the renamed fixture\n' >&2
    return 1
  }

  rust_dir="$work_dir/rust"
  rust_bin="$rust_dir/bin"
  mkdir -p "$rust_bin"
  cp "$root/.github/scripts/rustcheck.sh" "$rust_dir/rustcheck.sh"
  cat >"$rust_bin/cargo" <<'EOF'
#!/usr/bin/env bash
while (($#)); do
  if [[ "$1" == --target-dir ]]; then
    shift
    target_dir=$1
  fi
  shift
done
mkdir -p "$target_dir/release"
case "$(uname -s 2>/dev/null)" in
CYGWIN* | MINGW* | MSYS*) suffix=.exe ;;
*) suffix= ;;
esac
: >"$target_dir/release/celestia-url-reference$suffix"
chmod +x "$target_dir/release/celestia-url-reference$suffix"
EOF
  cat >"$rust_bin/find" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
  chmod +x "$rust_bin/cargo" "$rust_bin/find"
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_bin/cargo" PATH="$rust_bin:$PATH" \
        bash ./rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust release check ignored a failed artefact inventory\n' >&2
    return 1
  }
  grep -Fq 'Failed to inventory release artefacts' <<<"$output" || {
    printf 'Rust release output omitted the inventory failure:\n%s\n' \
      "$output" >&2
    return 1
  }

  wait "$change_pid"
  change_pid=
  wait "$currency_pid"
  currency_pid=
  wait "$action_pid"
  action_pid=
)

main
