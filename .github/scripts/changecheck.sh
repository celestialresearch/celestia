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

docs=false
policy=false
ci=false
go=false
rust=false
dependencies=false
compatibility=false
full=false
count=0
paths=

reset_classification() {
  docs=false
  policy=false
  ci=false
  go=false
  rust=false
  dependencies=false
  compatibility=false
  full=false
  count=0
}

mark_full() {
  docs=true
  policy=true
  ci=true
  go=true
  rust=true
  dependencies=true
  compatibility=true
  full=true
}

classify_path() {
  local path=$1

  count=$((count + 1))
  case "$path" in
  README.md | docs/*)
    docs=true
    policy=true
    ;;
  AGENTS.md | LICENSE | policies/*)
    policy=true
    ;;
  .github/dependabot.yml)
    ci=true
    dependencies=true
    ;;
  .github/scripts/windows-shellcheck.ps1)
    ci=true
    compatibility=true
    ;;
  .github/workflows/* | .github/codeql/*)
    mark_full
    ;;
  .github/scripts/changecheck.sh | .github/scripts/devcheck.sh | \
    .github/scripts/verification_test.sh | .github/scripts/policycheck.sh | \
    .github/scripts/licencecheck.sh | .github/scripts/actioncheck.sh | \
    .github/scripts/modcheck.sh | .github/scripts/rustcheck.sh | \
    .github/scripts/coveragecheck.sh)
    mark_full
    ;;
  .github/generated/* | generated/*)
    mark_full
    ;;
  go.mod | go.sum)
    go=true
    dependencies=true
    compatibility=true
    ;;
  Cargo.toml | Cargo.lock | deny.toml | rust-toolchain.toml | */Cargo.toml)
    rust=true
    dependencies=true
    compatibility=true
    ;;
  *.go)
    go=true
    compatibility=true
    case "$path" in
    internal/workerprotocolv1/* | internal/urladmission/*)
      mark_full
      ;;
    esac
    ;;
  *.rs)
    rust=true
    compatibility=true
    case "$path" in
    worker/*/src/*)
      mark_full
      ;;
    esac
    ;;
  .editorconfig | .gitattributes | .gitignore | .golangci.yml)
    mark_full
    ;;
  *)
    mark_full
    ;;
  esac
}

emit() {
  printf 'docs=%s\n' "$docs"
  printf 'policy=%s\n' "$policy"
  printf 'ci=%s\n' "$ci"
  printf 'go=%s\n' "$go"
  printf 'rust=%s\n' "$rust"
  printf 'dependencies=%s\n' "$dependencies"
  printf 'compatibility=%s\n' "$compatibility"
  printf 'full=%s\n' "$full"
}

main() {
  local base=${1:-}
  local head=${2:-}
  local path

  reset_classification
  if [[ -z "$base" || -z "$head" ]] ||
    ! git cat-file -e "$base^{commit}" 2>/dev/null ||
    ! git cat-file -e "$head^{commit}" 2>/dev/null; then
    mark_full
    emit
    return
  fi

  paths=$(mktemp "${TMPDIR:-/tmp}/celestia-changecheck.XXXXXX")
  case "$paths" in
  "${TMPDIR:-/tmp}"/celestia-changecheck.*) ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$paths" >&2
    return 1
    ;;
  esac
  trap '[[ -z "${paths:-}" ]] || rm -f -- "$paths"' EXIT HUP INT TERM
  if ! git diff --name-only -z "$base" "$head" >"$paths"; then
    mark_full
    emit
    return
  fi
  while IFS= read -r -d '' path; do
    classify_path "$path"
  done <"$paths"
  if ((count == 0)); then
    mark_full
  fi
  emit
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
