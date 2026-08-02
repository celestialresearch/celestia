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
family_dir="$root/.github/scripts/verification"
family_repo=$root
family_prefix=.github/scripts/verification
families=(
  lint_test.sh
  action_test.sh
  devcheck_config_test.sh
  rust_config_test.sh
  rust_integration_test.sh
  rust_artefact_test.sh
  coverage_test.sh
  source_policy_test.sh
  licence_test.sh
  release_artefact_test.sh
)

fixture_mode=${1:-}
case "$fixture_mode" in
"") ;;
--fixture)
  family_dir=${CELESTIA_VERIFICATION_FAMILY_DIR:?}
  family_repo=${CELESTIA_VERIFICATION_FAMILY_REPO:?}
  family_prefix=${CELESTIA_VERIFICATION_FAMILY_PREFIX:?}
  ;;
*)
  printf 'Usage: verification_test.sh [--fixture]\n' >&2
  exit 2
  ;;
esac
if [[ "$fixture_mode" != --fixture ]] &&
  [[ -n "${CELESTIA_VERIFICATION_FAMILY_DIR+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_REPO+x}" ||
    -n "${CELESTIA_VERIFICATION_FAMILY_PREFIX+x}" ||
    -n "${CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT+x}" ]]; then
  printf 'verification family overrides require fixture mode\n' >&2
  exit 2
fi

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
terminate_family() {
  local pid=$1

  kill -TERM -- "-$pid" 2>/dev/null || true
  kill -KILL -- "-$pid" 2>/dev/null || true
}

# shellcheck disable=SC2329 # Invoked through the registered exit handler.
cleanup_driver() {
  local status=0

  if [[ -n "${snapshot_root:-}" && -e "$snapshot_root" ]]; then
    chmod -R u+w -- "$snapshot_root" || status=1
    rm -rf -- "$snapshot_root" || status=1
  fi
  if [[ -n "${driver_work:-}" && -e "$driver_work" ]]; then
    rm -rf -- "$driver_work" || status=1
  fi
  return "$status"
}

# shellcheck disable=SC2329 # Invoked by registered signal and exit traps.
finish_driver() {
  local status=$1

  trap - EXIT HUP INT TERM
  if [[ -n "${driver_pid:-}" ]]; then
    terminate_family "$driver_pid" 2>/dev/null || true
    wait "$driver_pid" 2>/dev/null || true
    driver_pid=
  fi
  if ! cleanup_driver; then
    status=1
  fi
  exit "$status"
}

snapshot_family_tree() {
  local destination=$1
  local manifest=$2
  local bindings=$3
  local binding
  local binding_digest
  local binding_index=0
  local binding_size
  local copied_digest
  local copied_size
  local metadata
  local mode
  local path
  local record
  local relative
  local source
  local stage
  local target

  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    path=${record#*$'\t'}
    mode=${metadata%% *}
    metadata=${metadata#* }
    stage=${metadata##* }
    case "$path" in
    "$family_prefix"/*) relative=${path#"$family_prefix/"} ;;
    *)
      printf 'verification snapshot escaped its prefix\n' >&2
      return 1
      ;;
    esac
    case "$relative" in
    "" | /* | *$'\n'* | *$'\r'* | ../* | */../* | */..)
      printf 'verification snapshot has an unsupported path\n' >&2
      return 1
      ;;
    esac
    if [[ "$stage" != 0 ||
      ("$mode" != 100644 && "$mode" != 100755) ]]; then
      printf 'verification snapshot has an unsupported entry: %s\n' \
        "$relative" >&2
      return 1
    fi
    source="$family_repo/$path"
    target="$destination/$relative"
    binding="$bindings/$binding_index/object"
    binding_index=$((binding_index + 1))
    if [[ -L "$source" || ! -f "$source" ]]; then
      printf 'verification snapshot source is unavailable: %s\n' \
        "$relative" >&2
      return 1
    fi
    mkdir -p -- "${target%/*}"
    mkdir -- "${binding%/*}"
    if ! cat -- "$source" >"$binding" ||
      [[ -L "$source" || ! -f "$source" ]] ||
      ! cmp -s -- "$source" "$binding"; then
      printf 'verification snapshot source changed: %s\n' "$relative" >&2
      return 1
    fi
    binding_size=$(wc -c <"$binding")
    binding_digest=$(git hash-object --no-filters -- "$binding")
    chmod 400 -- "$binding"
    chmod 500 -- "${binding%/*}"
    if [[ -n "${CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT:-}" ]]; then
      if [[ -L "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT" ||
        ! -f "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT" ||
        ! -x "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT" ]]; then
        printf 'verification snapshot checkpoint is unavailable\n' >&2
        return 1
      fi
      CELESTIA_VERIFICATION_SNAPSHOT_PATH=$relative \
        "$CELESTIA_VERIFICATION_SNAPSHOT_CHECKPOINT"
    fi
    copied_size=$(wc -c <"$binding")
    if [[ -L "$source" || ! -f "$source" ]] ||
      [[ "$copied_size" != "$binding_size" ]] ||
      ! cmp -s -- "$source" "$binding" ||
      ! cp -- "$binding" "$target"; then
      printf 'verification snapshot source changed: %s\n' "$relative" >&2
      return 1
    fi
    copied_size=$(wc -c <"$target")
    copied_digest=$(git hash-object --no-filters -- "$target")
    if [[ -L "$target" || ! -f "$target" ]] ||
      [[ "$copied_size" != "$binding_size" ||
        "$copied_digest" != "$binding_digest" ]] ||
      ! cmp -s -- "$binding" "$target"; then
      printf 'verification snapshot copy differs: %s\n' "$relative" >&2
      return 1
    fi
    if [[ "$mode" == 100755 ]]; then
      chmod 500 -- "$target"
    else
      chmod 400 -- "$target"
    fi
  done <"$manifest"
  find "$destination" -type d -exec chmod 500 {} +
}

snapshot_size() {
  local size

  size=$(wc -c <"$1") || return 1
  size=${size//[[:space:]]/}
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$size"
}

snapshot_matches() {
  local path=$1
  local expected_size=$2
  local expected_identity=$3
  local identity
  local size

  [[ ! -L "$path" && -f "$path" ]] || return 1
  size=$(snapshot_size "$path") || return 1
  [[ "$size" == "$expected_size" ]] || return 1
  identity=$(git hash-object --no-filters -- "$path") || return 1
  [[ "$identity" == "$expected_identity" ]]
}

main() (
  local work=$1
  local snapshot=$2
  local declared
  local bindings
  local executed
  local family
  local manifest
  local master
  local master_identity
  local master_size
  local path
  local source

  declared="$work/declared"
  bindings="$work/bindings"
  executed="$work/executed"
  manifest="$work/manifest"
  master="$work/source.tar"
  source="$work/source"
  mkdir -- "$bindings" "$source"
  printf '%s\n' "${families[@]}" >"$declared"
  bash "$root/.github/scripts/testcheck.sh" verification "$family_dir" \
    "$declared" "$family_repo" "$family_prefix"
  git -C "$family_repo" ls-files --stage -z -- "$family_prefix" >"$manifest"
  snapshot_family_tree "$source" "$manifest" "$bindings"
  tar -cf "$master" -C "$source" .
  master_size=$(snapshot_size "$master") || return 1
  master_identity=$(git hash-object --no-filters -- "$master") || return 1
  chmod 400 -- "$master"
  chmod -R u+w -- "$source" "$bindings"
  rm -rf -- "$source" "$bindings"
  for family in "${families[@]}"; do
    chmod -R u+w -- "$snapshot"
    rm -rf -- "$snapshot"
    mkdir -- "$snapshot"
    if ! snapshot_matches "$master" "$master_size" "$master_identity"; then
      printf 'verification master snapshot identity differs\n' >&2
      return 1
    fi
    tar -xf "$master" -C "$snapshot"
    path="$snapshot/$family"
    if [[ -L "$path" || ! -f "$path" || ! -x "$path" ]]; then
      printf 'verification family is unavailable: %s\n' "$family" >&2
      return 1
    fi
    "$path"
    printf '%s\n' "$family" >>"$executed"
  done
  if ! cmp -s "$declared" "$executed"; then
    printf 'verification families lacked ordered execution\n' >&2
    return 1
  fi
)

driver_pid=
driver_work=
snapshot_root=
trap 'finish_driver $?' EXIT
trap 'finish_driver 129' HUP
trap 'finish_driver 130' INT
trap 'finish_driver 143' TERM
driver_work=$(mktemp -d "${TMPDIR:-/tmp}/celestia-verification-driver.XXXXXX")
snapshot_root=$(mktemp -d \
  "$root/.github/scripts/.verification-family.XXXXXX")
set -m
main "$driver_work" "$snapshot_root" "$@" &
set +m
driver_pid=$!
set +e
wait "$driver_pid"
status=$?
set -e
driver_pid=
exit "$status"
