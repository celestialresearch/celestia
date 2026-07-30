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
git_bin=${CELESTIA_GIT_BIN:-git}
source_inventory=$(mktemp "${TMPDIR:-/tmp}/celestia-policy.XXXXXX")
trap 'rm -f -- "$source_inventory"' EXIT

fail() {
  printf '%s\n' "$1" >&2
  status=1
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

check_test_skips() {
  local matches

  matches=$(git_grep --untracked -n -I \
    -E '(^|[^[:alnum:]_])t\.Skip(f|Now)?[[:space:]]*\(' -- \
    '*.go')
  [[ -z "$matches" ]] || {
    printf '%s\n' "$matches" >&2
    fail 'Go tests must not skip cases'
  }
  matches=$(git_grep --untracked -n -I \
    -E '#[[:space:]]*\[[[:space:]]*ignore([[:space:]]|\]|=)' -- \
    '*.rs')
  [[ -z "$matches" ]] || {
    printf '%s\n' "$matches" >&2
    fail 'Rust tests must not ignore cases'
  }
}

check_suppressions() {
  local allow_marker='#[al''low('
  local allow_open=false
  local allow_reason=false
  local allow_rule=false
  local allow_start=0
  local file
  local line
  local line_number
  local nolint_marker='//no''lint'
  local nosec_marker='#no''sec'
  local rule
  local rules
  local shellcheck_marker='# shell''check disable='
  local suffix

  while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    case "$file" in
    *.go | *.rs | *.sh | *.bash | *.ps1) ;;
    *) continue ;;
    esac
    line_number=0
    allow_open=false
    allow_reason=false
    allow_rule=false
    while IFS= read -r line || [[ -n "$line" ]]; do
      line_number=$((line_number + 1))
      if [[ "$allow_open" == true ]]; then
        if [[ "$line" =~ ^[[:space:]]*clippy::[a-z0-9_]+,[[:space:]]*$ ]] &&
          [[ "$allow_rule" == false ]]; then
          rule=${line#*clippy::}
          rule=${rule%%,*}
          if [[ "$rule" == all ]]; then
            fail "$file:$allow_start: invalid Clippy suppression"
            allow_open=false
          else
            allow_rule=true
          fi
        elif [[ "$line" =~ ^[[:space:]]*reason[[:space:]]*=[[:space:]]*\"[^\"]+\"[[:space:]]*$ ]] &&
          [[ "$allow_reason" == false ]]; then
          allow_reason=true
        elif [[ "$line" =~ ^[[:space:]]*\)\][[:space:]]*$ ]] &&
          [[ "$allow_rule" == true && "$allow_reason" == true ]]; then
          allow_open=false
        else
          fail "$file:$allow_start: invalid Clippy suppression"
          allow_open=false
        fi
        continue
      fi
      if [[ "$line" == *"$nosec_marker"* ]]; then
        suffix=${line#*"$nosec_marker"}
        [[ "$suffix" =~ ^[[:space:]]+G[0-9]+(,G[0-9]+)*[[:space:]]+--[[:space:]]+[^[:space:]].*$ ]] ||
          fail "$file:$line_number: invalid gosec suppression"
      fi
      if [[ "$line" == *"$nolint_marker"* ]]; then
        suffix=${line#*"$nolint_marker"}
        if [[ "$suffix" =~ ^:([a-z0-9][a-z0-9,-]*)[[:space:]]+--[[:space:]]+[^[:space:]].*$ ]]; then
          rules=${BASH_REMATCH[1]}
          [[ ",$rules," != *,all,* ]] ||
            fail "$file:$line_number: invalid golangci-lint suppression"
        else
          fail "$file:$line_number: invalid golangci-lint suppression"
        fi
      fi
      if [[ "$line" == *"$shellcheck_marker"* ]]; then
        suffix=${line#*"$shellcheck_marker"}
        [[ "$suffix" =~ ^SC[0-9]+(,SC[0-9]+)*[[:space:]]+#[[:space:]]+[^[:space:]].*$ ]] ||
          fail "$file:$line_number: invalid ShellCheck suppression"
      fi
      if [[ "$line" == *"$allow_marker"* ]]; then
        if [[ "$line" =~ ^[[:space:]]*#\[allow\(clippy::([a-z0-9_]+),[[:space:]]*reason[[:space:]]*=[[:space:]]*\"[^\"]+\"\)\][[:space:]]*$ ]]; then
          if [[ "${BASH_REMATCH[1]}" == all ]]; then
            fail "$file:$line_number: invalid Clippy suppression"
          else
            continue
          fi
        fi
        if [[ "$line" =~ ^[[:space:]]*#\[allow\([[:space:]]*$ ]]; then
          allow_open=true
          allow_reason=false
          allow_rule=false
          allow_start=$line_number
          continue
        fi
        fail "$file:$line_number: invalid Clippy suppression"
      fi
    done <"$file"
    if [[ "$allow_open" == true ]]; then
      fail "$file:$allow_start: incomplete Clippy suppression"
    fi
  done <"$source_inventory"
}

is_generated_source() {
  local count=0
  local file=$1
  local line

  while IFS= read -r line; do
    if [[ "$line" =~ ^//\ Code\ generated\ .*\ DO\ NOT\ EDIT\.$ ]]; then
      return 0
    fi
    count=$((count + 1))
    ((count < 30)) || break
  done <"$file"
  return 1
}

check_source_files() {
  local base
  local file
  local intent
  local lines
  local stem

  while IFS= read -r -d '' file; do
    file=./$file
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

    if is_generated_source "$file"; then
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
  done <"$source_inventory"
}

check_module
if ! "$git_bin" ls-files -co --exclude-standard -z >"$source_inventory"; then
  printf 'Failed to inventory repository files\n' >&2
  exit 1
fi
check_markers
check_private_keys
check_test_skips
check_suppressions
check_source_files
exit "$status"
