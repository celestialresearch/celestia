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

mode=${1:-config}
cache_root=${CELESTIA_CACHE_DIR:-.cache}

rust_version() {
  awk -F'"' '$1 ~ /^[[:space:]]*rust-version/ { print $2; exit }' Cargo.toml
}

toolchain_version() {
  awk -F'"' '$1 ~ /^[[:space:]]*channel/ { print $2; exit }' rust-toolchain.toml
}

fixture_rust_version() {
  awk -F'"' '$1 ~ /^[[:space:]]*rust-version/ { print $2; exit }' \
    worker/qualification-fixtures/Cargo.toml
}

workflow_tools() {
  awk '
    FNR == 1 {
      in_action = 0
      in_block = 0
    }
    {
      indent = match($0, /[^ ]/) - 1
    }
    /^[[:space:]]*uses:[[:space:]]*taiki-e\/install-action@/ {
      action_indent = indent - 2
      in_action = 1
      next
    }
    in_action && indent <= action_indent && $0 !~ /^[[:space:]]*$/ {
      in_action = 0
    }
    in_action && /^[[:space:]]*tool:[[:space:]]*\|[[:space:]]*(#.*)?$/ {
      block_indent = match($0, /[^ ]/) - 1
      in_block = 1
      next
    }
    in_block {
      if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) {
        next
      }
      indent = match($0, /[^ ]/) - 1
      if (indent <= block_indent) {
        in_block = 0
        next
      }
      line = $0
      sub(/^[[:space:]]*/, "", line)
      sub(/[[:space:]]+#.*$/, "", line)
      print line
    }
  ' .github/workflows/*.yml
}

workflow_tool_version() {
  tool=$1
  matches=$(
    workflow_tools |
      sed -n "s/^${tool}@\\([^[:space:]]*\\).*$/\\1/p" |
      sort -u
  )
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
  if [[ "$count" -ne 1 ]]; then
    printf 'Expected one active workflow version for %s, found %s\n' \
      "$tool" "$count" >&2
    return 1
  fi
  printf '%s\n' "$matches"
}

check_config() {
  workflow_rust=false
  if [[ -f .github/workflows/main.yml ]] &&
    workflow_tools | grep -Eq '^(rust|cargo-[a-z0-9-]+)@'; then
    workflow_rust=true
  fi
  if [[ ! -f Cargo.toml && ! -f rust-toolchain.toml &&
    "$workflow_rust" == false ]]; then
    return
  fi
  if [[ ! -f Cargo.toml || ! -f rust-toolchain.toml ||
    "$workflow_rust" == false ]]; then
    printf 'Incomplete Rust configuration: manifest, toolchain and workflow pins must coexist\n'
    return 1
  fi

  manifest=$(rust_version)
  fixture=$(fixture_rust_version)
  toolchain=$(toolchain_version)
  if ! workflow=$(workflow_tool_version rust 2>&1); then
    printf '%s\n' "$workflow"
    return 1
  fi
  if [[ -z "$manifest" || -z "$fixture" ||
    "$manifest" != "$fixture" ||
    "$manifest" != "$toolchain" ||
    "$manifest" != "$workflow" ]]; then
    printf 'Rust version mismatch: manifest=%s fixture=%s toolchain=%s workflow=%s\n' \
      "$manifest" "$fixture" "$toolchain" "$workflow"
    return 1
  fi
}

check_tool() {
  command_name=$1
  workflow_name=$2
  cargo_bin=${CARGO_BIN:-cargo}
  if ! expected=$(workflow_tool_version "$workflow_name" 2>&1); then
    printf '%s\n' "$expected"
    return 1
  fi
  if [[ -z "$expected" ]]; then
    printf 'Missing pinned Rust helper in main workflow: %s\n' "$workflow_name"
    return 1
  fi
  if ! output=$("$cargo_bin" "$command_name" --version 2>&1); then
    printf 'Required Rust helper is unavailable: cargo %s\n' "$command_name"
    return 1
  fi
  actual=${output##* }
  if [[ "$actual" != "$expected" ]]; then
    printf 'Rust helper version mismatch: %s expected=%s actual=%s\n' \
      "$workflow_name" "$expected" "$actual"
    return 1
  fi
}

check_tools() {
  expected=$(toolchain_version)
  rustc_bin=${RUSTC_BIN:-rustc}
  if ! output=$("$rustc_bin" --version 2>&1); then
    printf 'Required Rust compiler is unavailable\n'
    return 1
  fi
  actual=$(printf '%s\n' "$output" | awk '{ print $2; exit }')
  if [[ "$actual" != "$expected" ]]; then
    printf 'Rust compiler version mismatch: expected=%s actual=%s\n' \
      "$expected" "$actual"
    return 1
  fi

  check_tool llvm-cov cargo-llvm-cov
  if [[ "${DEVCHECK_SUPPLY_CHAIN:-true}" == true ]]; then
    check_tool audit cargo-audit
    check_tool deny cargo-deny
  fi
}

release_exe_suffix() {
  case "$(uname -s 2>/dev/null)" in
  CYGWIN* | MINGW* | MSYS*) printf '.exe' ;;
  *) printf '' ;;
  esac
}

check_release_outputs() (
  local inventory

  cargo_bin=${CARGO_BIN:-cargo}
  mkdir -p "$cache_root"
  target_dir=$(mktemp -d "$cache_root/release-artefacts.XXXXXX")

  # shellcheck disable=SC2329 # Invoked by the EXIT and signal trap.
  cleanup() {
    case "$target_dir" in
    "$cache_root"/release-artefacts.*) rm -rf -- "$target_dir" ;;
    esac
  }

  trap cleanup EXIT HUP INT TERM
  "$cargo_bin" build --workspace --release --locked --target-dir "$target_dir"

  release_dir=$target_dir/release
  # Cargo keeps build metadata beside the release outputs. It is not part of
  # the distributable directory and must not weaken the allowlist below.
  rm -rf -- "$release_dir/.fingerprint" "$release_dir/build" \
    "$release_dir/deps" "$release_dir/examples" "$release_dir/incremental"
  # Cargo's build lock is coordination state, not a distributable artefact.
  rm -f -- "$release_dir/.cargo-artifact-lock" \
    "$release_dir/.cargo-build-lock" \
    "$release_dir/.cargo-lock"
  expected=celestia-url-reference$(release_exe_suffix)
  expected_metadata=("celestia-url-reference.d")
  if [[ "$expected" == *.exe ]]; then
    expected_metadata+=("celestia_url_reference.pdb")
  fi
  inventory=$target_dir/release-inventory
  if ! find "$release_dir" -mindepth 1 -print0 >"$inventory"; then
    printf 'Failed to inventory release build outputs\n' >&2
    return 1
  fi
  seen=false
  while IFS= read -r -d '' path; do
    file=${path#"$release_dir/"}
    if [[ -d "$path" ]]; then
      printf 'Unexpected release directory: %s\n' "$file"
      return 1
    fi
    if [[ -L "$path" ]]; then
      printf 'Unexpected release symlink: %s\n' "$file"
      return 1
    fi
    if [[ ! -f "$path" ]]; then
      printf 'Unexpected release build output: %s\n' "$file"
      return 1
    fi
    if [[ "$file" == "$expected" ]]; then
      if [[ ! -x "$path" && "$file" != *.exe ]]; then
        printf 'Release artefact is not executable: %s\n' "$expected"
        return 1
      fi
      seen=true
      continue
    fi
    metadata=false
    for allowed in "${expected_metadata[@]}"; do
      if [[ "$file" == "$allowed" ]]; then
        metadata=true
        break
      fi
    done
    if [[ "$metadata" == true ]]; then
      if [[ -x "$path" ]]; then
        printf 'Invalid release metadata: %s\n' "$file"
        return 1
      fi
      continue
    fi
    if [[ -x "$path" || "$file" == *.exe ]]; then
      printf 'Unexpected release executable: %s\n' "$file"
    else
      printf 'Unexpected release build output: %s\n' "$file"
    fi
    return 1
  done <"$inventory"

  if [[ "$seen" != true ]]; then
    printf 'Missing release executable: %s\n' "$expected"
    return 1
  fi
)

case "$mode" in
config)
  check_config
  ;;
tools)
  check_config
  check_tools
  ;;
artefacts)
  check_release_outputs
  ;;
*)
  printf 'Usage: rustcheck.sh artefacts|config|tools\n' >&2
  exit 2
  ;;
esac
