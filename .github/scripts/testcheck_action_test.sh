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
work=$(mktemp -d "${TMPDIR:-/tmp}/testcheck-action.XXXXXX")

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

action_repo="$work/repo"
action_dir="$action_repo/actioncheck"
mkdir -p "$action_dir"
git -C "$action_repo" init -q
git -C "$action_repo" config core.autocrlf false
action_families='remote_release_test.sh
cache_test.sh
inventory_test.sh
permissions_test.sh'
while IFS= read -r family; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$action_dir/$family"
  chmod +x "$action_dir/$family"
done <<<"$action_families"
git -C "$action_repo" add -f actioncheck
while IFS= read -r family; do
  git -C "$action_repo" update-index --chmod=+x "actioncheck/$family"
done <<<"$action_families"
printf '%s\n' "$action_families" >"$work/executed"
bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/executed" "$action_repo" actioncheck >/dev/null

printf '%s\n' "$action_families" | sed '$d' >"$work/incomplete"
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/incomplete" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted omitted execution\n' >&2
  exit 1
fi
printf '%s\n' "$action_families" | sed '1{h;d};2{p;g;}' >"$work/reordered"
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/reordered" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted reordered execution\n' >&2
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$action_dir/unexpected_test.sh"
chmod +x "$action_dir/unexpected_test.sh"
git -C "$action_repo" add -f actioncheck/unexpected_test.sh
git -C "$action_repo" update-index --chmod=+x actioncheck/unexpected_test.sh
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/executed" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted an unexpected family\n' >&2
  exit 1
fi
git -C "$action_repo" rm -q -f actioncheck/unexpected_test.sh

rm -- "$action_dir/cache_test.sh"
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/executed" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted a missing family\n' >&2
  exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$action_dir/cache_test.sh"
chmod +x "$action_dir/cache_test.sh"
git -C "$action_repo" add actioncheck/cache_test.sh
git -C "$action_repo" update-index --chmod=+x actioncheck/cache_test.sh

git -C "$action_repo" update-index --chmod=-x actioncheck/permissions_test.sh
if bash "$root/.github/scripts/testcheck.sh" action "$action_dir" \
  "$work/executed" "$action_repo" actioncheck >/dev/null 2>&1; then
  printf 'action inventory accepted a non-executable family\n' >&2
  exit 1
fi
