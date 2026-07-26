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
cache_root=${CELESTIA_CACHE_DIR:-.cache}

usage() {
  printf 'Usage: %s verify|currency|cached-currency\n' "${0##*/}" >&2
}

action_files() {
  find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print0
  find . -type f \( -name 'action.yml' -o -name 'action.yaml' \) \
    ! -path './.git/*' ! -path './.cache/*' -print0
}

remote_actions() {
  local file

  while IFS= read -r -d '' file; do
    awk -v file="$file" '
      /^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/ {
        line = $0
        sub(/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/, "", line)
        if (line !~ /^(\.\/|docker:\/\/)/) {
          print file ":" NR ":" line
        }
      }
    ' "$file"
  done < <(action_files)
}

parse_action() {
  local entry=$1
  local location value reference annotation

  location=${entry%%:*:*}
  value=${entry#*:*:}
  reference=${value%%[[:space:]]*}
  annotation=${value#"$reference"}
  annotation=${annotation#"${annotation%%[![:space:]]*}"}

  if [[ ! "$reference" =~ ^([^/@]+/[^/@]+)(/[^@]+)?@([0-9a-f]{40})$ ]]; then
    printf '%s: remote actions must use a full 40-character commit SHA\n' "$location" >&2
    return 1
  fi
  ACTION_REPOSITORY=${BASH_REMATCH[1]}
  ACTION_SHA=${BASH_REMATCH[3]}

  if [[ ! "$annotation" =~ ^#[[:space:]]+(v[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
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
      $2 > major ||
      ($2 == major && $3 > minor) ||
      ($2 == major && $3 == minor && $4 > patch) {
        major = $2
        minor = $3
        patch = $4
        latest = $0
      }
      END { print latest }
    '
}

check_actions() {
  local check_currency=$1
  local checked_latest=$'\n'
  local checked_tags=$'\n'
  local entry expected latest status=0
  local key

  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    if ! parse_action "$entry"; then
      status=1
      continue
    fi

    if [[ "$check_currency" == true ]]; then
      key="$ACTION_REPOSITORY@$ACTION_TAG"
      if [[ "$checked_tags" != *$'\n'"$key"$'\n'* ]]; then
        if ! expected=$(tag_sha "$ACTION_REPOSITORY" "$ACTION_TAG"); then
          status=1
          continue
        fi
        if [[ -z "$expected" || "$expected" != "$ACTION_SHA" ]]; then
          printf '%s@%s does not resolve to %s\n' \
            "$ACTION_REPOSITORY" "$ACTION_TAG" "$ACTION_SHA" >&2
          status=1
        fi
        checked_tags+="$key"$'\n'
      fi
      if [[ "$checked_latest" != *$'\n'"$ACTION_REPOSITORY"$'\n'* ]]; then
        if ! latest=$(latest_tag "$ACTION_REPOSITORY"); then
          status=1
          continue
        fi
        if [[ -z "$latest" ]]; then
          printf '%s has no discoverable stable semantic release\n' \
            "$ACTION_REPOSITORY" >&2
          status=1
        elif [[ "$latest" != "$ACTION_TAG" ]]; then
          if bash ./.github/scripts/currencycheck.sh \
            allows action "$ACTION_REPOSITORY" "$ACTION_TAG"; then
            printf '%s retains %s by documented exception; latest is %s\n' \
              "$ACTION_REPOSITORY" "$ACTION_TAG" "$latest"
          else
            printf '%s uses %s; latest stable release is %s\n' \
              "$ACTION_REPOSITORY" "$ACTION_TAG" "$latest" >&2
            status=1
          fi
        fi
        checked_latest+="$ACTION_REPOSITORY"$'\n'
      fi
    fi
  done < <(remote_actions)

  return "$status"
}

cache_key() {
  local file

  {
    while IFS= read -r -d '' file; do
      git hash-object "$file"
    done < <(action_files)
    git hash-object .github/scripts/actioncheck.sh
    git --version
  } | git hash-object --stdin
}

cached_currency() {
  local key cache_file temporary_cache
  local max_age_minutes=${ACTIONCHECK_CACHE_MAX_AGE_MINUTES:-1440}

  if [[ ! "$max_age_minutes" =~ ^[0-9]+$ ]]; then
    printf 'ACTIONCHECK_CACHE_MAX_AGE_MINUTES must be a non-negative integer\n' >&2
    return 2
  fi

  key=$(cache_key)
  cache_file="$cache_root/actioncheck/$key"
  if ((max_age_minutes > 0)) &&
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
  action_files >/dev/null

  case "$1" in
  verify)
    check_actions false
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
