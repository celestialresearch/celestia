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

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

status=0

fail() {
  printf '%s\n' "$1" >&2
  status=1
}

git_grep() {
  local result
  local grep_status

  set +e
  result=$(git grep "$@" 2>/dev/null)
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
  local kind
  local matches
  local marker

  for kind in '' 'RSA ' 'EC ' 'DSA ' 'OPENSSH '; do
    marker="BEGIN ${kind}PRIVATE KEY"
    matches=$(git_grep --untracked -n -I -F "$marker" -- . \
      ':(exclude).cache/**')
    [[ -z "$matches" ]] || {
      printf '%s\n' "$matches" >&2
      fail 'private-key material found in repository files'
    }
  done
}

check_source_files() {
  local base
  local file
  local intent
  local lines
  local stem

  while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    case "$file" in
    *.go | *.rs | *.c | *.cc | *.cpp | *.cxx | *.h | *.hh | *.hpp | *.hxx) ;;
    *) continue ;;
    esac

    base=${file##*/}
    stem=${base%.*}
    intent=${stem%_test}

    case "$intent" in
    additional | more | extended | misc | extra | helper | helpers | util | \
      utils | common)
      fail "$file: vague accumulation filename is prohibited"
      ;;
    esac

    if [[ "$base" == coverage_test.go ]]; then
      fail "$file: use an intent-named residual coverage file"
    fi

    if head -n 30 "$file" |
      grep -Eq '^// Code generated .* DO NOT EDIT\.$'; then
      continue
    fi

    lines=$(wc -l <"$file")
    lines=${lines//[[:space:]]/}
    case "$base" in
    *_test.*)
      if ((lines > 1000)); then
        fail "$file: test file exceeds the 1,000-line maximum"
      fi
      ;;
    *)
      if ((lines > 800)); then
        fail "$file: source file exceeds the 800-line exceptional maximum"
      fi
      ;;
    esac
  done < <(git ls-files -co --exclude-standard -z)
}

check_module
check_markers
check_private_keys
check_source_files
exit "$status"
