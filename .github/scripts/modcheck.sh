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

git_bin=${CELESTIA_GIT_BIN:-git}

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
cache_root=${CELESTIA_CACHE_DIR:-.cache}

usage() {
  printf 'Usage: %s verify|diff|cached-diff|update\n' "${0##*/}" >&2
}

tool_packages() {
  awk '
    /^[[:space:]]*tool[[:space:]]*\(/ { in_tools = 1; next }
    in_tools && /^[[:space:]]*\)/ { in_tools = 0; next }
    in_tools {
      value = $1
      if (value != "") {
        print value
      }
      next
    }
    /^[[:space:]]*tool[[:space:]]+[^()[:space:]]+/ { print $2 }
  ' go.mod
}

verify_modules() {
  go mod verify
  go mod tidy -diff
}

update_modules() {
  local package
  local packages
  local tools

  packages=$(go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' \
    ./... 2>/dev/null | sed '/^[[:space:]]*$/d')
  if [[ -n "$packages" ]]; then
    go get -u ./...
  fi
  tools=$(tool_packages)
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    go get -tool "$package@latest"
  done <<<"$tools"
  go mod tidy
  go mod verify
}

compare_file() {
  local current=$1
  local updated=$2

  if [[ -f "$current" && -f "$updated" ]]; then
    diff -u --label "a/$current" --label "b/$current" \
      "$current" "$updated" || return 1
    return
  fi
  if [[ -f "$current" ]]; then
    printf '%s exists in the repository but not after update\n' "$current"
    return 1
  fi
  if [[ -f "$updated" ]]; then
    printf '%s would be created by the update\n' "$current"
    sed 's/^/+/' "$updated"
    return 1
  fi
}

check_update_diff() (
  local status=0
  local work_dir file inventory files

  work_dir=$(mktemp -d "${TMPDIR:-/tmp}/celestia-modcheck.XXXXXX")
  case "$work_dir" in
  "${TMPDIR:-/tmp}"/celestia-modcheck.*) ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$work_dir" >&2
    return 1
    ;;
  esac
  trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM

  inventory=$work_dir/inventory
  files=$work_dir/files
  if ! "$git_bin" ls-files -co --exclude-standard -z >"$inventory"; then
    printf 'Failed to inventory module inputs\n' >&2
    return 1
  fi
  : >"$files"
  while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    printf '%s\0' "$file" >>"$files"
  done <"$inventory"
  tar --null -T "$files" -cf - |
    tar -xf - -C "$work_dir"
  if ! (
    cd -- "$work_dir"
    update_modules
  ); then
    return 1
  fi

  compare_file go.mod "$work_dir/go.mod" || status=1
  compare_file go.sum "$work_dir/go.sum" || status=1
  rm -rf -- "$work_dir"
  trap - EXIT HUP INT TERM
  return "$status"
)

cache_key() {
  {
    "$git_bin" hash-object go.mod
    if [[ -f go.sum ]]; then
      "$git_bin" hash-object go.sum
    else
      printf 'no-go-sum\n'
    fi
    "$git_bin" hash-object .github/scripts/modcheck.sh
    go env GOVERSION GOOS GOARCH
  } | "$git_bin" hash-object --stdin
}

check_cached_update_diff() {
  local cache_file
  local cache_key_value
  local marker temporary_cache
  local max_age_minutes=${MODCHECK_CACHE_MAX_AGE_MINUTES:-1440}

  if [[ ! "$max_age_minutes" =~ ^[0-9]+$ ]]; then
    printf 'MODCHECK_CACHE_MAX_AGE_MINUTES must be a non-negative integer\n' >&2
    return 2
  fi

  cache_key_value=$(cache_key)
  cache_file="$cache_root/modcheck/$cache_key_value"
  if ((max_age_minutes > 0)) &&
    [[ -f "$cache_file" && ! -L "$cache_file" ]] &&
    IFS= read -r marker <"$cache_file" &&
    [[ "$marker" == "$cache_key_value" ]] &&
    [[ -n "$(find "$cache_file" -mmin "-$max_age_minutes" -print 2>/dev/null)" ]]; then
    printf 'module currency cached\n'
    return
  fi

  verify_modules
  check_update_diff
  mkdir -p -- "$(dirname -- "$cache_file")"
  temporary_cache=$(mktemp "$(dirname -- "$cache_file")/.module.XXXXXX")
  if ! printf '%s\n' "$cache_key_value" >"$temporary_cache"; then
    rm -f -- "$temporary_cache"
    return 1
  fi
  if ! mv -f -- "$temporary_cache" "$cache_file"; then
    rm -f -- "$temporary_cache"
    return 1
  fi
}

if (($# != 1)); then
  usage
  exit 2
fi

case "$1" in
verify)
  verify_modules
  ;;
diff)
  verify_modules
  check_update_diff
  ;;
cached-diff)
  check_cached_update_diff
  ;;
update)
  update_modules
  ;;
*)
  usage
  exit 2
  ;;
esac
