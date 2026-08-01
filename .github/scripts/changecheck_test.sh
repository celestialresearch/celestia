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
fixture_repo=

cd "$root"
# shellcheck source=.github/scripts/changecheck.sh
source ./.github/scripts/changecheck.sh

cleanup() {
  [[ -z "$fixture_repo" ]] || rm -rf -- "$fixture_repo"
}

assert_value() {
  local expected=$1
  local key=$2
  local output=$3
  local actual

  actual=$(awk -F= -v key="$key" '$1 == key { print $2; exit }' <<<"$output")
  [[ "$actual" == "$expected" ]] || {
    printf '%s: expected %s, found %s\n%s\n' \
      "$key" "$expected" "$actual" "$output" >&2
    return 1
  }
}

commit_file() {
  local repo=$1
  local path=$2
  local directory

  directory=${path%/*}
  if [[ "$directory" != "$path" ]]; then
    mkdir -p -- "$repo/$directory"
  fi
  printf '%s\n' "$path" >"$repo/$path"
  git -C "$repo" add -A
  git -C "$repo" commit -q -m "$path"
}

classify_path_directly() {
  reset_classification
  classify_path "$1"
  emit
}

main() {
  local output
  local base

  fixture_repo=$(mktemp -d "${TMPDIR:-/tmp}/celestia-changecheck.XXXXXX")
  case "$fixture_repo" in
  "${TMPDIR:-/tmp}"/celestia-changecheck.*) ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$fixture_repo" >&2
    return 1
    ;;
  esac
  trap cleanup EXIT HUP INT TERM
  git -C "$fixture_repo" init -q
  git -C "$fixture_repo" config user.name Fixture
  git -C "$fixture_repo" config user.email fixture@example.invalid
  git -C "$fixture_repo" config commit.gpgsign false
  git -C "$fixture_repo" config core.autocrlf false
  git -C "$fixture_repo" commit --allow-empty -q -m base

  output=$(classify_path_directly docs/operation.md)
  assert_value true docs "$output"
  assert_value true policy "$output"
  assert_value false full "$output"

  output=$(
    classify_path_directly docs/contracts/governed_url_reference_v1.json
  )
  assert_value true full "$output"

  output=$(classify_path_directly policies/commit.md)
  assert_value true policy "$output"
  assert_value false full "$output"

  output=$(classify_path_directly .github/workflows/codeql.yml)
  assert_value true ci "$output"
  assert_value true full "$output"

  output=$(classify_path_directly .github/workflows/compatibility.yml)
  assert_value true ci "$output"
  assert_value true compatibility "$output"
  assert_value true full "$output"

  output=$(classify_path_directly go.mod)
  assert_value true go "$output"
  assert_value true dependencies "$output"
  assert_value true compatibility "$output"
  assert_value true full "$output"

  output=$(classify_path_directly worker/url-reference/Cargo.toml)
  assert_value true rust "$output"
  assert_value true dependencies "$output"
  assert_value true full "$output"

  output=$(classify_path_directly internal/operation/urlreference/transform/urlreference.go)
  assert_value true go "$output"
  assert_value true full "$output"

  for path in cmd/newtool/main.go internal/newpackage/new.go; do
    output=$(classify_path_directly "$path")
    assert_value true go "$output"
    assert_value true full "$output"
  done

  for path in \
    worker/url-reference/build.rs \
    worker/url-reference/benches/bench.rs \
    tools/helper.rs; do
    output=$(classify_path_directly "$path")
    assert_value true rust "$output"
    assert_value true full "$output"
  done

  for path in \
    internal/attemptstore/store.go \
    internal/execution/supervision/supervisor_windows.go \
    internal/operation/urlreference/protocol/protocol.go \
    internal/urladmission/admission.go \
    internal/urloperation/operation_windows.go \
    worker/url-reference/src/main.rs \
    worker/url-reference/tests/process.rs \
    .github/scripts/devcheck.sh \
    .github/scripts/windows-shellcheck.ps1 \
    .github/generated/probe.yml \
    tools/actionpolicy/main.go \
    tools/sourcepolicy/main.go \
    .editorconfig \
    unknown.file; do
    output=$(classify_path_directly "$path")
    assert_value true full "$output"
  done

  base=$(git -C "$fixture_repo" rev-parse HEAD)
  output=$(
    cd "$fixture_repo"
    bash "$root/.github/scripts/changecheck.sh" "$base" HEAD
  )
  assert_value true full "$output"
  output=$(
    cd "$fixture_repo"
    bash "$root/.github/scripts/changecheck.sh" missing HEAD
  )
  assert_value true full "$output"
  base=$(git -C "$fixture_repo" rev-parse HEAD)
  commit_file "$fixture_repo" docs/mixed.md
  commit_file "$fixture_repo" internal/operation/urlreference/transform/mixed.go
  output=$(
    cd "$fixture_repo"
    bash "$root/.github/scripts/changecheck.sh" "$base" HEAD
  )
  assert_value true docs "$output"
  assert_value true go "$output"
  assert_value true full "$output"

  base=$(git -C "$fixture_repo" rev-parse HEAD)
  git -C "$fixture_repo" mv docs/mixed.md renamed.unknown
  git -C "$fixture_repo" commit -q -m rename
  output=$(
    cd "$fixture_repo"
    bash "$root/.github/scripts/changecheck.sh" "$base" HEAD
  )
  assert_value true full "$output"

  commit_file "$fixture_repo" internal/operation/urlreference/transform/renamed.go
  base=$(git -C "$fixture_repo" rev-parse HEAD)
  git -C "$fixture_repo" mv \
    internal/operation/urlreference/transform/renamed.go \
    docs/renamed.md
  git -C "$fixture_repo" commit -q -m production-rename
  output=$(
    cd "$fixture_repo"
    bash "$root/.github/scripts/changecheck.sh" "$base" HEAD
  )
  assert_value true docs "$output"
  assert_value true go "$output"
  assert_value true full "$output"

  commit_file "$fixture_repo" internal/operation/urlreference/protocol/deleted.go
  base=$(git -C "$fixture_repo" rev-parse HEAD)
  git -C "$fixture_repo" rm -q internal/operation/urlreference/protocol/deleted.go
  git -C "$fixture_repo" commit -q -m deletion
  output=$(
    cd "$fixture_repo"
    bash "$root/.github/scripts/changecheck.sh" "$base" HEAD
  )
  assert_value true full "$output"
}

main
