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
work_dir=$(new_verification_work verification-rust-config)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-rust-config failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

grep -Fq "while [[ -n \"\$directory\" ]]" \
  "$root/.github/scripts/rustcheck.sh" || {
  printf 'Rust config check omits the filesystem root\n' >&2
  return 1
}
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

for variable in RUSTFLAGS RUSTC RUSTDOC RUSTC_BOOTSTRAP \
  RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER; do
  set +e
  output=$(
    cd "$rust_dir" &&
      env "$variable=hostile" bash .github/scripts/rustcheck.sh config 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted inherited %s\n' "$variable" >&2
    return 1
  }
  grep -Fq "Uncontrolled Rust build environment: $variable" <<<"$output" || {
    printf 'Rust config check omitted the %s diagnostic:\n%s\n' \
      "$variable" "$output" >&2
    return 1
  }
done

for variable in rustflags RuStFlAgS; do
  set +e
  output=$(
    cd "$rust_dir" &&
      env "$variable=hostile" bash .github/scripts/rustcheck.sh config 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted inherited %s\n' "$variable" >&2
    return 1
  }
  grep -Fq "Uncontrolled Rust build environment: $variable" <<<"$output" || {
    printf 'Rust config check omitted the %s diagnostic:\n%s\n' \
      "$variable" "$output" >&2
    return 1
  }
done

output=$(
  cd "$rust_dir" &&
    env -i PATH="$PATH" HOME="$HOME" SYSTEMROOT="${SYSTEMROOT:-}" \
      bash .github/scripts/rustcheck.sh config 2>&1
) || {
  printf 'Rust config check rejected a clean environment:\n%s\n' \
    "$output" >&2
  return 1
}

mkdir -p "$rust_dir/external-cargo-home"
printf '%s\n' '[build]' 'rustflags = ["--cap-lints=allow"]' \
  >"$rust_dir/external-cargo-home/config.toml"
for variable in cargo_home CaRgO_HoMe; do
  set +e
  output=$(
    cd "$rust_dir" &&
      env "$variable=$rust_dir/external-cargo-home" \
        bash .github/scripts/rustcheck.sh config 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted inherited %s\n' "$variable" >&2
    return 1
  }
  grep -Fq 'External Cargo configuration is prohibited' <<<"$output" || {
    printf 'Rust config check omitted the %s diagnostic:\n%s\n' \
      "$variable" "$output" >&2
    return 1
  }
done
rm -rf -- "$rust_dir/external-cargo-home"

mkdir -p "$rust_dir/.cargo"
printf '%s\n' '[build]' 'rustflags = ["--cap-lints=allow"]' \
  >"$rust_dir/.cargo/config.toml"
set +e
output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
status=$?
set -e
rm -rf -- "$rust_dir/.cargo"
[[ "$status" -ne 0 ]] || {
  printf 'Rust config check accepted untracked Cargo configuration\n' >&2
  return 1
}
grep -Fq 'Untracked Cargo configuration is prohibited' <<<"$output" || {
  printf 'Rust config check omitted the untracked-config diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

mkdir -p "$rust_dir/linked-cargo"
printf '%s\n' '[build]' 'rustflags = ["--cap-lints=allow"]' \
  >"$rust_dir/linked-cargo/config.toml"
if ln -s "$rust_dir/linked-cargo" "$rust_dir/.cargo" 2>/dev/null &&
  [[ -L "$rust_dir/.cargo" ]]; then
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  rm -- "$rust_dir/.cargo"
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted a linked Cargo directory\n' >&2
    return 1
  }
  grep -Fq 'Cargo configuration directory escapes the repository' \
    <<<"$output" || {
    printf 'Rust config check omitted the linked-directory diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
fi
rm -rf -- "$rust_dir/linked-cargo" "$rust_dir/.cargo"

if [[ "$(uname -s)" == MINGW* ]] &&
  command -v cygpath >/dev/null 2>&1 &&
  command -v cmd.exe >/dev/null 2>&1; then
  mkdir -p "$rust_dir/junction-cargo"
  printf '%s\n' '[build]' 'rustflags = ["--cap-lints=allow"]' \
    >"$rust_dir/junction-cargo/config.toml"
  CEL_CARGO_LINK=$(cygpath -w "$rust_dir/.cargo")
  CEL_CARGO_TARGET=$(cygpath -w "$rust_dir/junction-cargo")
  MSYS2_ARG_CONV_EXCL='*' cmd.exe /d /c mklink /J \
    "$CEL_CARGO_LINK" "$CEL_CARGO_TARGET" >/dev/null
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  rm -- "$rust_dir/.cargo"
  rm -rf -- "$rust_dir/junction-cargo"
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted a junction-backed Cargo directory\n' \
      >&2
    return 1
  }
  grep -Fq 'Cargo configuration directory escapes the repository' \
    <<<"$output" || {
    printf 'Rust config check omitted the junction diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
fi

if [[ "$(uname -s)" != MINGW* ]] &&
  command -v mkfifo >/dev/null 2>&1; then
  mkdir -p "$rust_dir/.cargo"
  mkfifo "$rust_dir/.cargo/config"
  set +e
  (
    cd "$rust_dir" &&
      bash .github/scripts/rustcheck.sh config
  ) >"$rust_dir/cargo-fifo-output" 2>&1 &
  fifo_pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 0.1
    kill -0 "$fifo_pid" 2>/dev/null || break
  done
  if kill -0 "$fifo_pid" 2>/dev/null; then
    terminate_child "$fifo_pid"
    printf 'Rust config check blocked while inspecting a Cargo FIFO\n' >&2
    return 1
  fi
  wait "$fifo_pid"
  status=$?
  set -e
  fifo_pid=
  rm -- "$rust_dir/.cargo/config"
  rmdir -- "$rust_dir/.cargo"
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted a Cargo FIFO\n' >&2
    return 1
  }
  grep -Fq 'Cargo configuration must be a regular file' \
    "$rust_dir/cargo-fifo-output" || {
    printf 'Rust config check omitted the Cargo FIFO diagnostic:\n' >&2
    cat "$rust_dir/cargo-fifo-output" >&2
    return 1
  }
  rm -- "$rust_dir/cargo-fifo-output"
fi

printf '%s\n' '[package]' 'rust-version = "1.94.0"' '' \
  '[lints.rust]' 'non_ascii_idents = "deny"' \
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
printf '%s\n' '[package]' 'rust-version = "1.94.1"' '' \
  '[lints.rust]' 'non_ascii_idents = "deny"' \
  >"$rust_dir/worker/qualification-fixtures/Cargo.toml"

cp "$rust_dir/Cargo.toml" "$rust_dir/Cargo.toml.lints"
sed '/unsafe_code = "forbid"/d' "$rust_dir/Cargo.toml.lints" \
  >"$rust_dir/Cargo.toml"
set +e
output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
status=$?
set -e
mv "$rust_dir/Cargo.toml.lints" "$rust_dir/Cargo.toml"
[[ "$status" -ne 0 ]] || {
  printf 'Rust config check accepted a missing unsafe-code prohibition\n' >&2
  return 1
}
grep -Fq 'Rust lint policy mismatch' <<<"$output" || {
  printf 'Rust config check omitted the lint-policy diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

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
  >"$rust_dir/.github/workflows/nightly.yaml"
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
  "$rust_dir/.github/workflows/nightly.yaml"

)

main
