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

if [[ -n "${GOFLAGS:-}" && ! "$GOFLAGS" =~ ^-p=[1-9][0-9]*$ ]]; then
  printf 'Uncontrolled Go policy environment: GOFLAGS\n' >&2
  exit 1
fi
if [[ -n "${GOENV:-}" && "$GOENV" != off ]]; then
  printf 'Uncontrolled Go policy environment: GOENV\n' >&2
  exit 1
fi
export GOENV=off GOWORK=off

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

status=0
git_bin=${CELESTIA_GIT_BIN:-git}

fail() {
  printf '%s\n' "$1" >&2
  status=1
}

start_policy_check() {
  policy_name=$1
  status=0
  policy_started=$(date +%s)
}

finish_policy_check() {
  local finished

  finished=$(date +%s)
  if ((status == 0)); then
    printf '        %-34s[PASS] %ss\n' \
      "$policy_name" "$((finished - policy_started))"
  else
    printf '        %-34s[FAIL] %ss\n' \
      "$policy_name" "$((finished - policy_started))"
  fi
  return "$status"
}

git_grep() {
  local result
  local grep_status

  set +e
  result=$("$git_bin" grep "$@" 2>/dev/null)
  grep_status=$?
  set -e
  if ((grep_status > 1)); then
    printf 'git grep failed while enforcing repository policy\n' >&2
    return "$grep_status"
  fi
  printf '%s' "$result"
}

check_module() {
  local module_path
  local version

  module_path=$(awk '$1 == "module" { print $2; exit }' go.mod)
  version=$(awk '$1 == "go" { print $2; exit }' go.mod)

  [[ "$module_path" == celestia.research/* ]] ||
    fail 'go.mod: module path must use the celestia.research/ prefix'
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    fail 'go.mod: Go version must be pinned at patch level'
}

check_workspace_files() {
  local path

  for path in go.work go.work.sum; do
    if [[ -e "$path" || -L "$path" ]]; then
      fail "$path: Go workspace files are prohibited"
    fi
  done
}

check_markers() {
  local output

  output=$(git_grep --untracked -n -I \
    -E '^(<<<<<<< [^<]|=======$|>>>>>>> [^>])' -- . \
    ':(exclude).cache/**')
  [[ -z "$output" ]] || {
    printf '%s\n' "$output" >&2
    fail 'unresolved merge markers found'
  }
}

check_private_keys() {
  local matches

  matches=$(git_grep --untracked -n -I \
    -E 'BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY' -- . \
    ':(exclude).cache/**')
  [[ -z "$matches" ]] || {
    printf '%s\n' "$matches" >&2
    fail 'private-key material found in repository files'
  }
}

check_source_policy() {
  if ! go run ./tools/sourcepolicy all; then
    status=1
    return
  fi
  bash ./.github/scripts/depguardcheck.sh || status=1
}

case "${1:-all}" in
all)
  start_policy_check 'Source Policy'
  check_source_policy
  finish_policy_check || exit 1
  start_policy_check 'Module'
  check_module
  finish_policy_check || exit 1
  start_policy_check 'Workspace'
  check_workspace_files
  finish_policy_check || exit 1
  start_policy_check 'Merge Markers'
  check_markers
  finish_policy_check || exit 1
  start_policy_check 'Private Keys'
  check_private_keys
  finish_policy_check || exit 1
  ;;
module)
  check_module
  ;;
markers)
  check_markers
  ;;
source-files)
  go run ./tools/sourcepolicy source-files || status=1
  ;;
suppressions)
  go run ./tools/sourcepolicy suppressions || status=1
  ;;
manifest)
  go run ./tools/sourcepolicy manifest || status=1
  ;;
architecture)
  go run ./tools/sourcepolicy architecture || status=1
  if ((status == 0)); then
    bash ./.github/scripts/depguardcheck.sh || status=1
  fi
  ;;
workspace)
  check_workspace_files
  ;;
test-skips)
  go run ./tools/sourcepolicy test-skips || status=1
  ;;
*)
  printf 'Usage: %s [all|architecture|manifest|markers|module|source-files|suppressions|test-skips|workspace]\n' \
    "${0##*/}" >&2
  exit 2
  ;;
esac
exit "$status"
