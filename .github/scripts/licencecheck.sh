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

usage() {
  printf 'Usage: %s verify|diff|cached-diff|update|apply\n' "${0##*/}" >&2
}

expected=$(printf '%s\n' \
  'Copyright © 2026 @sudocelestia. All rights reserved.' \
  '' \
  'PROPRIETARY AND CONFIDENTIAL SOURCE CODE.' \
  '' \
  'No licence, permission or authorisation is granted to use, copy, modify,' \
  'compile, execute, distribute, publish, sublicense or otherwise exploit this' \
  'file, except to the limited extent unavoidably permitted by applicable law' \
  "or GitHub's Terms of Service." \
  '' \
  'See the LICENSE file at the repository root for the complete terms.')

eligible_files() {
  local file

  while IFS= read -r -d '' file; do
    [[ -n "$(style_for "$file")" ]] || continue
    printf '%s\0' "$file"
  done < <(git ls-files -co --exclude-standard -z)
}

style_for() {
  case "$1" in
  *.go | *.rs | *.c | *.cc | *.cpp | *.cxx | *.h | *.hh | *.hpp | *.hxx | \
    *.java | *.js | *.jsx | *.ts | *.tsx | *.swift | *.kt | *.kts | \
    *.proto | *.zig)
    printf 'slash\n'
    ;;
  *.sql)
    printf 'dash\n'
    ;;
  *.bat | *.cmd)
    printf 'rem\n'
    ;;
  *.sh | *.bash | *.py | *.ps1 | *.rb | *.pl | */Dockerfile | */Makefile)
    printf 'hash\n'
    ;;
  *)
    if IFS= read -r first <"$1" && [[ "$first" == '#!'* ]]; then
      printf 'hash\n'
    fi
    ;;
  esac
}

current_header() {
  local file=$1
  local first

  IFS= read -r first <"$file" || true
  if [[ "$first" == '#!'* ]]; then
    tail -n +2 "$file"
  else
    cat "$file"
  fi | head -n 10
}

render_header() {
  local line
  local prefix

  case "$1" in
  hash) prefix='#' ;;
  slash) prefix='//' ;;
  dash) prefix='--' ;;
  rem) prefix='REM' ;;
  esac
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      printf '%s %s\n' "$prefix" "$line"
    else
      printf '%s\n' "$prefix"
    fi
  done <<<"$expected"
}

render_file() {
  local file=$1
  local style=$2
  local first

  IFS= read -r first <"$file" || true
  if [[ "$first" == '#!'* ]]; then
    printf '%s\n' "$first"
    render_header "$style"
    printf '\n'
    tail -n +2 "$file"
  else
    render_header "$style"
    printf '\n'
    cat "$file"
  fi
}

has_notice_marker() {
  head -n 20 "$1" | grep -Fq 'PROPRIETARY AND CONFIDENTIAL SOURCE CODE.'
}

verify_files() {
  local file status=0 style

  while IFS= read -r -d '' file; do
    style=$(style_for "$file")
    if [[ "$(current_header "$file")" != "$(render_header "$style")" ]]; then
      printf '%s: missing or incorrect proprietary header\n' "$file" >&2
      status=1
    fi
  done < <(eligible_files)
  return "$status"
}

diff_files() {
  local file status=0 style temporary

  while IFS= read -r -d '' file; do
    style=$(style_for "$file")
    [[ "$(current_header "$file")" != "$(render_header "$style")" ]] || continue
    if has_notice_marker "$file"; then
      printf '%s: malformed proprietary header requires manual correction\n' \
        "$file" >&2
      status=1
      continue
    fi
    temporary=$(mktemp "${TMPDIR:-/tmp}/celestia-licence.XXXXXX")
    render_file "$file" "$style" >"$temporary"
    diff -u --label "a/${file#./}" --label "b/${file#./}" \
      "$file" "$temporary" || true
    rm -f -- "$temporary"
    status=1
  done < <(eligible_files)
  return "$status"
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

update_files() {
  local directory file mode style temporary

  while IFS= read -r -d '' file; do
    style=$(style_for "$file")
    [[ "$(current_header "$file")" != "$(render_header "$style")" ]] || continue
    if has_notice_marker "$file"; then
      printf '%s: malformed proprietary header requires manual correction\n' \
        "$file" >&2
      return 1
    fi
  done < <(eligible_files)

  while IFS= read -r -d '' file; do
    style=$(style_for "$file")
    [[ "$(current_header "$file")" != "$(render_header "$style")" ]] || continue
    directory=$(dirname -- "$file")
    temporary=$(mktemp "$directory/.licencecheck.XXXXXX")
    render_file "$file" "$style" >"$temporary"
    mode=$(file_mode "$file")
    chmod "$mode" "$temporary"
    mv -f -- "$temporary" "$file"
    printf 'updated %s\n' "$file"
  done < <(eligible_files)
}

cache_key() {
  local file

  {
    while IFS= read -r -d '' file; do
      git hash-object "$file"
    done < <(eligible_files)
    git hash-object .github/scripts/licencecheck.sh
  } | git hash-object --stdin
}

cached_diff() {
  local cache_file key
  local max_age_minutes=${LICENCECHECK_CACHE_MAX_AGE_MINUTES:-1440}

  [[ "$max_age_minutes" =~ ^[0-9]+$ ]] || {
    printf 'LICENCECHECK_CACHE_MAX_AGE_MINUTES must be a non-negative integer\n' >&2
    return 2
  }
  key=$(cache_key)
  cache_file=".cache/licencecheck/$key"
  if ((max_age_minutes > 0)) &&
    [[ -n "$(find "$cache_file" -mmin "-$max_age_minutes" -print 2>/dev/null)" ]]; then
    printf 'licence headers cached\n'
    return
  fi
  verify_files
  mkdir -p -- "$(dirname -- "$cache_file")"
  printf '%s\n' "$key" >"$cache_file"
}

if (($# != 1)); then
  usage
  exit 2
fi

case "$1" in
verify)
  verify_files
  ;;
diff)
  diff_files
  ;;
cached-diff)
  cached_diff
  ;;
update | apply)
  update_files
  verify_files
  ;;
*)
  usage
  exit 2
  ;;
esac
