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

set -eu

mode=${1:-config}

rust_version() {
  awk -F'"' '$1 ~ /^[[:space:]]*rust-version/ { print $2; exit }' Cargo.toml
}

toolchain_version() {
  awk -F'"' '$1 ~ /^[[:space:]]*channel/ { print $2; exit }' rust-toolchain.toml
}

workflow_tools() {
  awk '
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
  ' .github/workflows/main.yml
}

workflow_tool_version() {
  tool=$1
  matches=$(
    workflow_tools |
      sed -n "s/^${tool}@\\([^[:space:]]*\\).*$/\\1/p"
  )
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
  if [[ "$count" -ne 1 ]]; then
    printf 'Expected one active workflow pin for %s, found %s\n' \
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
  toolchain=$(toolchain_version)
  if ! workflow=$(workflow_tool_version rust 2>&1); then
    printf '%s\n' "$workflow"
    return 1
  fi
  if [[ -z "$manifest" || "$manifest" != "$toolchain" ||
    "$manifest" != "$workflow" ]]; then
    printf 'Rust version mismatch: manifest=%s toolchain=%s workflow=%s\n' \
      "$manifest" "$toolchain" "$workflow"
    return 1
  fi
}

check_tool() {
  command_name=$1
  workflow_name=$2
  if ! expected=$(workflow_tool_version "$workflow_name" 2>&1); then
    printf '%s\n' "$expected"
    return 1
  fi
  if [[ -z "$expected" ]]; then
    printf 'Missing pinned Rust helper in main workflow: %s\n' "$workflow_name"
    return 1
  fi
  if ! output=$(cargo "$command_name" --version 2>&1); then
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
  if ! output=$(rustc --version 2>&1); then
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

case "$mode" in
config)
  check_config
  ;;
tools)
  check_config
  check_tools
  ;;
*)
  printf 'Usage: rustcheck.sh config|tools\n' >&2
  exit 2
  ;;
esac
