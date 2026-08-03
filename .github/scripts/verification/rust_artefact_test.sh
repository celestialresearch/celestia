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
work_dir=$(new_verification_work verification-rust-artefact)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-rust-artefact failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

rust_dir="$work_dir/rust"
mkdir -p "$rust_dir/.github/scripts" "$rust_dir/.github/workflows" \
  "$rust_dir/bin" "$rust_dir/worker/qualification-fixtures" \
  "$rust_dir/worker/url-reference"
cp "$root/.github/scripts/rustcheck.sh" "$rust_dir/.github/scripts/"
cat >"$rust_dir/.github/scripts/testcheck.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${TESTCHECK_CALL_LOG:?}"
EOF
chmod +x "$rust_dir/.github/scripts/testcheck.sh"
cat >"$rust_dir/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"

[workspace.package]
rust-version = "1.94.1"

[workspace.lints.rust]
non_ascii_idents = "deny"
unsafe_code = "forbid"
EOF
printf '%s\n' '[toolchain]' 'channel = "1.94.0"' \
  >"$rust_dir/rust-toolchain.toml"
printf '%s\n' '[package]' 'rust-version = "1.94.1"' '' \
  '[lints.rust]' 'non_ascii_idents = "deny"' \
  >"$rust_dir/worker/qualification-fixtures/Cargo.toml"
printf '%s\n' '[package]' 'name = "worker"' 'version = "0.0.0"' '' \
  '[lints]' 'workspace = true' \
  >"$rust_dir/worker/url-reference/Cargo.toml"
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
  "$rust_dir/.github/workflows/nightly.yaml"

printf '%s\n' '[toolchain]' 'channel = "1.94.1"' >"$rust_dir/rust-toolchain.toml"
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
test)
printf '%s\n' "$*" >>"${CARGO_CALL_LOG:?}"
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

testcheck_call_log="$rust_dir/testcheck-calls"
(
  cd "$rust_dir" &&
    TESTCHECK_CALL_LOG="$testcheck_call_log" \
      bash .github/scripts/rustcheck.sh tests
)
if [[ $(wc -l <"$testcheck_call_log" | tr -d ' ') -ne 1 ]] ||
  ! grep -Fxq 'rust' "$testcheck_call_log"; then
  printf 'Rust test check omitted the completion gate:\n' >&2
  cat "$testcheck_call_log" >&2
  return 1
fi

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
grep -Fq 'Unexpected release build output: unexpected.metadata' \
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
)

main
