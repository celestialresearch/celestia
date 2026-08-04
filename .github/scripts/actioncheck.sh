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

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
cache_root=${CELESTIA_CACHE_DIR:-.cache}
git_hash_bin=${ACTIONCHECK_GIT_HASH_BIN:-git}
currency_file=${ACTIONCHECK_CURRENCY_FILE:-.github/.currency}
currency_script=${ACTIONCHECK_CURRENCY_SCRIPT:-.github/scripts/currencycheck.sh}
module_file=${ACTIONCHECK_MODULE_FILE:-go.mod}
module_sum_file=${ACTIONCHECK_MODULE_SUM_FILE:-go.sum}
action_policy_dir=tools/actionpolicy

usage() {
  printf 'Usage: %s verify|currency|cached-currency\n' "${0##*/}" >&2
}

action_files() {
  local linked

  if ! linked=$(
    find .github/workflows -type l \
      \( -name '*.yml' -o -name '*.yaml' \) -print -quit
  ); then
    return 1
  fi
  if [[ -n "$linked" ]]; then
    printf '%s: linked workflow metadata is unsupported\n' "$linked" >&2
    return 1
  fi
  if ! linked=$(
    find . -type l \( -name 'action.yml' -o -name 'action.yaml' \) \
      ! -path './.git/*' ! -path './.cache/*' -print -quit
  ); then
    return 1
  fi
  if [[ -n "$linked" ]]; then
    printf '%s: linked action metadata is unsupported\n' "$linked" >&2
    return 1
  fi

  find .github/workflows -type f \
    \( -name '*.yml' -o -name '*.yaml' \) -print0 ||
    return
  find . -type f \
    \( -name 'action.yml' -o -name 'action.yaml' \) \
    ! -path './.git/*' ! -path './.cache/*' -print0
}

action_documents() {
  local inventory=$1
  local file

  while IFS= read -r -d '' file; do
    if [[ -L "$file" ]]; then
      printf '%s: linked action metadata is unsupported\n' "$file" >&2
      return 1
    fi
    printf '%s\0' "$file"
    cat -- "$file" || return
    printf '\0'
  done <"$inventory"
}

policy_files() {
  git ls-files -co --exclude-standard -z -- "$action_policy_dir"
}

toolchain_fingerprint() {
  go env GOVERSION GOOS GOARCH
}

remote_actions() (
  local inventory
  local mode=${1:-actions}

  inventory=$(mktemp "${TMPDIR:-/tmp}/celestia-actions.XXXXXX")
  trap 'rm -f -- "$inventory"' EXIT HUP INT TERM
  if ! action_files >"$inventory"; then
    return 1
  fi

  action_documents "$inventory" |
    go run "./$action_policy_dir" "$mode"
)

check_permissions() (
  local inventory

  inventory=$(mktemp "${TMPDIR:-/tmp}/celestia-permissions.XXXXXX")
  trap 'rm -f -- "$inventory"' EXIT HUP INT TERM
  action_files >"$inventory" || return
  action_documents "$inventory" |
    go run "./$action_policy_dir" permissions
)

parse_action() {
  local entry=$1
  local location value reference annotation

  ACTION_KIND=
  location=${entry%%:*:*}
  value=${entry#*:*:}
  reference=${value%%[[:space:]]*}
  annotation=${value#"$reference"}
  annotation=${annotation#"${annotation%%[![:space:]]*}"}

  if [[ "$reference" == ./* ]]; then
    printf '%s: local actions require an explicit reviewed resolution policy\n' \
      "$location" >&2
    return 1
  fi

  if [[ "$reference" == docker://* ]]; then
    if [[ ! "$reference" =~ ^docker://[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
      printf '%s: container images must use a lowercase SHA-256 digest\n' \
        "$location" >&2
      return 1
    fi
    ACTION_KIND=docker
    return
  fi

  if [[ ! "$reference" =~ ^([^/@]+/[^/@]+)(/[^@]+)?@([0-9a-f]{40})$ ]]; then
    printf '%s: remote actions must use a full 40-character commit SHA\n' "$location" >&2
    return 1
  fi
  ACTION_KIND=github
  ACTION_REPOSITORY=${BASH_REMATCH[1]}
  ACTION_SHA=${BASH_REMATCH[3]}

  if [[ ! "$annotation" =~ ^#[[:space:]]+(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$ ]]; then
    printf '%s: pinned actions require an exact trailing release annotation\n' "$location" >&2
    return 1
  fi
  ACTION_TAG=${BASH_REMATCH[1]}
}

git_ls_remote() {
  local attempts=${ACTIONCHECK_REMOTE_ATTEMPTS:-3}
  local delay=${ACTIONCHECK_RETRY_DELAY_SECONDS:-1}
  local attempt=1
  local output

  if [[ ! "$attempts" =~ ^[1-9][0-9]*$ ||
    ! "$delay" =~ ^[0-9]+$ ]]; then
    printf 'Action remote attempts must be positive and delay non-negative\n' >&2
    return 2
  fi
  while ! output=$(git ls-remote "$@" 2>&1); do
    if ((attempt >= attempts)); then
      printf '%s\n' "$output" >&2
      return 1
    fi
    printf 'Action remote lookup failed; retrying (%d/%d)\n' \
      "$attempt" "$attempts" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
  done
  printf '%s\n' "$output"
}

tag_sha() {
  local repository=$1
  local tag=$2
  local refs peeled

  if ! refs=$(git_ls_remote --tags "https://github.com/$repository.git" \
    "refs/tags/$tag" "refs/tags/$tag^{}"); then
    printf 'Could not resolve action tag: %s %s\n' "$repository" "$tag" >&2
    return 1
  fi
  peeled=$(awk '$2 ~ /\^\{\}$/ { print $1; exit }' <<<"$refs")
  if [[ -n "$peeled" ]]; then
    printf '%s\n' "$peeled"
    return
  fi
  awk '$2 !~ /\^\{\}$/ { print $1; exit }' <<<"$refs"
}

latest_tag() {
  local repository=$1
  local refs

  if ! refs=$(git_ls_remote --tags --refs "https://github.com/$repository.git"); then
    printf 'Could not list action releases: %s\n' "$repository" >&2
    return 1
  fi
  sed -n 's#^[0-9a-f]\{40\}[[:space:]]refs/tags/\(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$#\1#p' <<<"$refs" |
    awk -F '[v.]' '
      function decimal(value) {
        return value == "0" || value ~ /^[1-9][0-9]*$/
      }
      function compare(left, right) {
        if (length(left) != length(right)) {
          return length(left) > length(right) ? 1 : -1
        }
        if ("x" left == "x" right) {
          return 0
        }
        return "x" left > "x" right ? 1 : -1
      }
      decimal($2) && decimal($3) && decimal($4) &&
      (!found ||
        compare($2, major) > 0 ||
        (compare($2, major) == 0 && compare($3, minor) > 0) ||
        (compare($2, major) == 0 && compare($3, minor) == 0 &&
          compare($4, patch) > 0)) {
        found = 1
        major = $2
        minor = $3
        patch = $4
        latest = $0
      }
      END { print latest }
    '
}

check_actions() (
  local check_currency=$1
  local mode=${2:-actions}
  local tag_cache latest_cache
  local entries entry expected latest
  local key

  tag_cache=$(mktemp "${TMPDIR:-/tmp}/celestia-action-tags.XXXXXX")
  latest_cache=$(mktemp "${TMPDIR:-/tmp}/celestia-action-latest.XXXXXX")
  trap 'rm -f -- "$tag_cache" "$latest_cache"' EXIT HUP INT TERM

  if ! entries=$(remote_actions "$mode"); then
    return 1
  fi
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    if ! parse_action "$entry"; then
      return 1
    fi

    if [[ "$check_currency" == true && "$ACTION_KIND" == github ]]; then
      key="$ACTION_REPOSITORY@$ACTION_TAG"
      expected=$(awk -F '|' -v key="$key" '$1 == key { print $2; exit }' "$tag_cache")
      if [[ -z "$expected" ]]; then
        if ! expected=$(tag_sha "$ACTION_REPOSITORY" "$ACTION_TAG"); then
          return 1
        fi
        printf '%s|%s\n' "$key" "$expected" >>"$tag_cache"
      fi
      if [[ -z "$expected" || "$expected" != "$ACTION_SHA" ]]; then
        printf '%s@%s does not resolve to %s\n' \
          "$ACTION_REPOSITORY" "$ACTION_TAG" "$ACTION_SHA" >&2
        return 1
      fi
      latest=$(
        awk -F '|' -v repository="$ACTION_REPOSITORY" \
          '$1 == repository { print $2; exit }' "$latest_cache"
      )
      if [[ -z "$latest" ]]; then
        if ! latest=$(latest_tag "$ACTION_REPOSITORY"); then
          return 1
        fi
        printf '%s|%s\n' "$ACTION_REPOSITORY" "$latest" >>"$latest_cache"
      fi
      if [[ -z "$latest" ]]; then
        printf '%s has no discoverable stable semantic release\n' \
          "$ACTION_REPOSITORY" >&2
        return 1
      elif [[ "$latest" != "$ACTION_TAG" ]]; then
        if bash "$currency_script" \
          allows action "$ACTION_REPOSITORY" "$ACTION_TAG"; then
          printf '%s retains %s by documented exception; latest is %s\n' \
            "$ACTION_REPOSITORY" "$ACTION_TAG" "$latest"
        else
          printf '%s uses %s; latest stable release is %s\n' \
            "$ACTION_REPOSITORY" "$ACTION_TAG" "$latest" >&2
          return 1
        fi
      fi
    fi
  done <<<"$entries"

)

cache_key() (
  local inventory

  inventory=$(mktemp "${TMPDIR:-/tmp}/celestia-action-cache.XXXXXX")
  trap 'rm -f -- "$inventory"' EXIT HUP INT TERM
  if ! action_files >"$inventory"; then
    return 1
  fi
  if ! policy_files >>"$inventory"; then
    return 1
  fi
  printf '%s\0' \
    .github/scripts/actioncheck.sh \
    "$currency_file" \
    "$currency_script" \
    "$module_file" \
    "$module_sum_file" >>"$inventory"

  {
    xargs -0 "$git_hash_bin" hash-object -- <"$inventory"
    toolchain_fingerprint
    git --version
    date -u +%F
  } | git hash-object --stdin
)

cached_currency() {
  local key cache_file marker temporary_cache
  local max_age_minutes=${ACTIONCHECK_CACHE_MAX_AGE_MINUTES:-1440}

  if [[ ! "$max_age_minutes" =~ ^[0-9]+$ ]]; then
    printf 'ACTIONCHECK_CACHE_MAX_AGE_MINUTES must be a non-negative integer\n' >&2
    return 2
  fi

  key=$(cache_key)
  cache_file="$cache_root/actioncheck/$key"
  if ((max_age_minutes > 0)) &&
    [[ -f "$cache_file" && ! -L "$cache_file" ]] &&
    IFS= read -r marker <"$cache_file" &&
    [[ "$marker" == "$key" ]] &&
    [[ -n "$(find "$cache_file" -mmin "-$max_age_minutes" -print 2>/dev/null)" ]]; then
    printf 'action currency cached\n'
    return
  fi

  check_actions true
  mkdir -p -- "$(dirname -- "$cache_file")"
  temporary_cache=$(mktemp "$(dirname -- "$cache_file")/.action.XXXXXX")
  if ! printf '%s\n' "$key" >"$temporary_cache"; then
    rm -f -- "$temporary_cache"
    return 1
  fi
  if ! mv -f -- "$temporary_cache" "$cache_file"; then
    rm -f -- "$temporary_cache"
    return 1
  fi
}

main() {
  if (($# != 1)); then
    usage
    return 2
  fi

  case "$1" in
  verify)
    check_actions false verify
    ;;
  currency)
    check_actions true
    ;;
  cached-currency)
    cached_currency
    ;;
  *)
    usage
    return 2
    ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
